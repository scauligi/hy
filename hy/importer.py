import builtins
import importlib
import importlib.machinery
import importlib.util
import inspect
import os
import pkgutil
import py_compile
import runpy
import sys
import time
import types
import zipimport
from contextlib import contextmanager
from functools import wraps

import hy
from hy.compiler import hy_compile
from hy.reader import read_many

HY_MAGIC_STRING = b'\x46\x14'
HY_HDEP_VERSION = b'\x00\x01'
HY_SOURCE_SUFFIXES = [".hy"]
HY_DEP_SUFFIX = ".hyd"
PYTHON_SOURCE_SUFFIXES = importlib.machinery.SOURCE_SUFFIXES.copy()


@contextmanager
def _patch(obj, attr, replacement):
    _old = getattr(obj, attr)
    setattr(obj, attr, replacement)
    try:
        yield
    finally:
        setattr(obj, attr, _old)


def _patched(fn, obj, attr, replacement):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        with _patch(obj, attr, replacement):
            return fn(*args, **kwargs)

    return wrapper


@contextmanager
def loader_module_obj(loader):
    """Use the module object associated with a loader.

    This is intended to be used by a loader object itself, and primarily as a
    work-around for attempts to get module and/or file code from a loader
    without actually creating a module object.  Since Hy currently needs the
    module object for macro importing, expansion, and whatnot, using this will
    reconcile Hy with such attempts.

    For example, if we're first compiling a Hy script starting from
    `runhy.run_path`, the Hy compiler will need a valid module object in which
    to run, but, given the way `runhy.run_path` works, there might not be one
    yet (e.g. `__main__` for a .hy file).  We compensate by properly loading
    the module here.

    The function `inspect.getmodule` has a hidden-ish feature that returns
    modules using their associated filenames (via `inspect.modulesbyfile`),
    and, since the Loaders (and their delegate Loaders) carry a filename/path
    associated with the parent package, we use it as a more robust attempt to
    obtain an existing module object.

    When no module object is found, a temporary, minimally sufficient module
    object is created for the duration of the `with` body.
    """
    tmp_mod = False

    try:
        module = inspect.getmodule(None, _filename=loader.path)
    except KeyError:
        module = None

    if module is None:
        tmp_mod = True
        module = sys.modules.setdefault(loader.name, types.ModuleType(loader.name))
        module.__file__ = loader.path
        module.__name__ = loader.name

    try:
        yield module
    finally:
        if tmp_mod:
            del sys.modules[loader.name]


def _pyc_to_hdep_path(bytecode_path):
    dirname, basename = os.path.split(bytecode_path)
    name = basename.split(os.path.extsep, maxsplit=1)[0]
    return os.path.join(dirname, name) + HY_DEP_SUFFIX


def _dprint(*args, **kwargs):
    if os.environ.get("HY_DEBUG", False):
        print(*args, **kwargs, file=sys.stderr)


class HyLoader(importlib.machinery.SourceFileLoader):
    def get_data(self, path: str) -> bytes:
        if (
            path.endswith(tuple(importlib.machinery.BYTECODE_SUFFIXES))
            and hy.dont_read_bytecode
        ):
            raise FileNotFoundError(f"Not reading bytecode for {path!r}")
        return super().get_data(path)

    def get_code(self, fullname: str) -> types.CodeType | None:
        source_path = self.get_filename(fullname)
        try:
            bytecode_path = importlib.util.cache_from_source(source_path)
        except NotImplementedError:
            bytecode_path = None
        else:
            try:
                exc_details = {"name": fullname, "path": bytecode_path}
                self._validate_hdeps(bytecode_path, fullname, exc_details)
            except ImportError:
                pass
        res = super().get_code(fullname)
        return res

    def _validate_hdeps(self, bytecode_path, name, exc_details, seen=None):
        if seen is None:
            seen = set()
        hdep_path = _pyc_to_hdep_path(bytecode_path)
        try:
            fp = open(hdep_path, 'rb')
        except OSError:
            if not sys.dont_write_bytecode:
                try:
                    os.unlink(bytecode_path)
                except OSError:
                    pass
            pass
        else:
            try:
                with fp as stream:
                    magic = stream.read(len(HY_MAGIC_STRING))
                    if magic != HY_MAGIC_STRING:
                        msg = f'bad hdep magic for {name!r}'
                        _dprint(msg)
                        raise ImportError(msg, **exc_details)
                    version = stream.read(len(HY_HDEP_VERSION))
                    if version != HY_HDEP_VERSION:
                        msg = f'bad hdep version for {name!r}'
                        _dprint(msg)
                        raise ImportError(msg, **exc_details)
                    ctime = int.from_bytes(stream.read(4), 'little')
                    hdep_data = stream.read()
                    if hdep_data:
                        hdeps = map(bytes.decode, hdep_data.split(b"\0"))
                        for hdep in hdeps:
                            if hdep in seen:
                                continue
                            seen.add(hdep)
                            try:
                                spec = importlib.util.find_spec(hdep)
                            except ValueError as e:
                                raise ImportError("", **exc_details) from e
                            else:
                                if spec is not None and spec.has_location:
                                    st = spec.loader.path_stats(spec.origin)
                                    if st['mtime'] > ctime:
                                        msg = f'{exc_details["name"]}: macro dependency {hdep!r} is newer than cached bytecode'
                                        _dprint(msg)
                                        raise ImportError(msg, **exc_details)
                                    self._validate_hdeps(
                                        spec.cached, hdep, exc_details, seen
                                    )
            except ImportError as e:
                if not sys.dont_write_bytecode:
                    try:
                        os.unlink(bytecode_path)
                        os.unlink(hdep_path)
                    except OSError:
                        pass
                # re-raise to unroll up the chain deleting bytecode
                raise

    def _cache_bytecode(self, source_path, cache_path, data):
        super()._cache_bytecode(source_path, cache_path, data)
        hdep_path = _pyc_to_hdep_path(cache_path)
        module = self.module
        deps = sorted(
            set(
                macro.__module__.encode()
                for macro in [
                    *module._hy_macros.values(),
                    *module._hy_reader_macros.values(),
                ]
                if macro.__module__ != module.__name__
            )
        )
        ctime = (int(time.time()) & 0xFFFFFFFF).to_bytes(4, 'little')
        hdeps = bytearray(HY_MAGIC_STRING)
        hdeps.extend(HY_HDEP_VERSION)
        hdeps.extend(ctime)
        hdeps.extend(b"\0".join(deps))
        self.set_data(hdep_path, hdeps)

    def source_to_code(self, data, path, *, _optimize=-1):
        if os.environ.get("HY_MESSAGE_WHEN_COMPILING"):
            print("Compiling", path, file=sys.stderr)
        source = data.decode("utf-8")
        hy_tree = read_many(source, filename=path, skip_shebang=True)
        with loader_module_obj(self) as self.module:
            data = hy_compile(hy_tree, self.module)

        return super().source_to_code(data, path, _optimize=_optimize)

    @classmethod
    def code_from_file(cls, filename):
        """Use PEP-302 loader to produce code for a given Hy source file."""
        full_fname = os.path.abspath(filename)
        fname_path, fname_file = os.path.split(full_fname)
        modname = os.path.splitext(fname_file)[0]
        loader = cls(modname, full_fname)
        code = loader.get_code(modname)

        return code


def _could_be_hy_src(filename):
    return os.path.isfile(filename) and (
        os.path.splitext(filename)[1] not in PYTHON_SOURCE_SUFFIXES
    )


def _runhy_get_code_from_file(run_name, fname):
    """A patch of `runpy._get_code_from_file` that will also run and cache Hy
    code.
    """
    # Check for bytecode first.  (This is what the `runpy` version does!)
    with open(fname, "rb") as f:
        code = pkgutil.read_code(f)

    if code is None:
        if _could_be_hy_src(fname):
            code = HyLoader.code_from_file(fname)
        else:
            # Try normal source
            with open(fname, "rb") as f:
                # This code differs from `runpy`'s only in that we
                # force decoding into UTF-8.
                source = f.read().decode("utf-8")
            code = compile(source, fname, "exec")

    return code, fname


# We create a separate version of runpy, "runhy", that prefers Hy source over
# Python.
runhy = types.SimpleNamespace(
    run_module=runpy.run_module,
    run_path=_patched(
        runpy.run_path, runpy, '_get_code_from_file', _runhy_get_code_from_file
    ),
)


# We also create a separate version of py_compile, "hyc_compile", that
# uses the hy compiler.
hyc_compile = types.SimpleNamespace(
    compile=_patched(
        py_compile.compile,
        importlib.machinery,
        'SourceFileLoader',
        HyLoader
        # XXX also write hdeps
    ),
    PyCompileError=py_compile.PyCompileError,
)


def _install_importer():
    if (".hy", False, False) not in zipimport._zip_searchorder:
        zipimport._zip_searchorder += ((".hy", False, False),)
        _py_compile_source = zipimport._compile_source

        def _hy_compile_source(pathname, source):
            if not pathname.endswith(".hy"):
                return _py_compile_source(pathname, source)
            return compile(
                hy_compile(
                    read_many(
                        source.decode("UTF-8"), filename=pathname, skip_shebang=True
                    ),
                    f"<zip:{pathname}>",
                ),
                pathname,
                "exec",
                dont_inherit=True,
            )

        zipimport._compile_source = _hy_compile_source

    from importlib._bootstrap_external import _get_supported_file_loaders

    importlib.machinery.SOURCE_SUFFIXES.extend(HY_SOURCE_SUFFIXES)

    def _fake():
        extensions = ExtensionFileLoader, _imp.extension_suffixes()
        source = SourceFileLoader, PYTHON_SOURCE_SUFFIXES
        hy_source = HyLoader, HY_SOURCE_SUFFIXES
        bytecode = SourcelessFileLoader, BYTECODE_SUFFIXES
        return [extensions, hy_source, source, bytecode]

    _get_supported_file_loaders.__code__ = _fake.__code__
    _get_supported_file_loaders.__globals__.update(
        {
            "HyLoader": HyLoader,
            "PYTHON_SOURCE_SUFFIXES": PYTHON_SOURCE_SUFFIXES,
            "HY_SOURCE_SUFFIXES": HY_SOURCE_SUFFIXES,
        }
    )

    for i, hook in enumerate(sys.path_hooks):
        if hook.__name__ == 'path_hook_for_FileFinder':
            sys.path_hooks[i] = importlib.machinery.FileFinder.path_hook(
                *_get_supported_file_loaders()
            )
            break

    #  This is actually needed; otherwise, pre-created finders assigned to the
    #  current dir (i.e. `''`) in `sys.path` will not catch absolute imports of
    #  directory-local modules!
    sys.path_importer_cache.clear()

    # Do this one just in case?
    importlib.invalidate_caches()


def _inject_builtins():
    """Inject the Hy core macros into Python's builtins if necessary"""
    if hasattr(builtins, "__hy_injected__"):
        return
    hy.macros.load_macros(builtins)
    # Set the marker so we don't inject again.
    builtins.__hy_injected__ = True
