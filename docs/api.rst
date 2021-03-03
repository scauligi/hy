API
===

.. hy:autofunction:: hy.eval

.. _special-forms:

Special Forms
-------------

.. hy:data:: ^

   The ``^`` symbol is used to denote annotations in three different contexts:

   - Standalone variable annotations.
   - Variable annotations in a setv call.
   - Function argument annotations.

   They implement `PEP 526 <https://www.python.org/dev/peps/pep-0526/>`_ and
   `PEP 3107 <https://www.python.org/dev/peps/pep-3107/>`_.

   Here is some example syntax of all three usages:

   :strong:`Examples`

   ::

      ; Annotate the variable x as an int (equivalent to `x: int`).
      (^int x)
      ; Can annotate with expressions if needed (equivalent to `y: f(x)`).
      (^(f x) y)

      ; Annotations with an assignment: each annotation (int, str) covers the term that
      ; immediately follows.
      ; Equivalent to: x: int = 1; y = 2; z: str = 3
      (setv ^int x 1 y 2 ^str z 3)

      ; Annotate a as an int, c as an int, and b as a str.
      ; Equivalent to: def func(a: int, b: str = None, c: int = 1): ...
      (defn func [^int a &optional ^str b ^int [c 1]] ...)

   The rules are:

   - The value to annotate with is the value that immediately follows the caret.
   - There must be no space between the caret and the value to annotate, otherwise it will be
     interpreted as a bitwise XOR like the Python operator.
   - The annotation always comes (and is evaluated) *before* the value being annotated. This is
     unlike Python, where it comes and is evaluated *after* the value being annotated.

   Note that variable annotations are only supported on Python 3.6+.

   For annotating items with generic types, the :hy:func:`of <hy.core.macros.of>` macro will likely be of use.

   .. note::

     Since the addition of type annotations, identifiers that start with ``^``
     are considered invalid as hy would try to read them as types.

.. _dot:

.. hy:data:: .

   .. versionadded:: 0.10.0

   ``.`` is used to perform attribute access on objects. It uses a small DSL
   to allow quick access to attributes and items in a nested data structure.

   :strong:`Examples`

   ::

       (. foo bar baz [(+ 1 2)] frob)

   Compiles down to:

   .. code-block:: python

       foo.bar.baz[1 + 2].frob

   ``.`` compiles its first argument (in the example, *foo*) as the object on
   which to do the attribute dereference. It uses bare symbols as attributes
   to access (in the example, *bar*, *baz*, *frob*), and compiles the contents
   of lists (in the example, ``[(+ 1 2)]``) for indexation. Other arguments
   raise a compilation error.

   Access to unknown attributes raises an :exc:`AttributeError`. Access to
   unknown keys raises an :exc:`IndexError` (on lists and tuples) or a
   :exc:`KeyError` (on dictionaries).

.. hy:function:: (fn [name &rest arags])

   ``fn``, like Python's ``lambda``, can be used to define an anonymous function.
   Unlike Python's ``lambda``, the body of the function can comprise several
   statements. The parameters are similar to ``defn``: the first parameter is
   vector of parameters and the rest is the body of the function. ``fn`` returns a
   new function. In the following example, an anonymous function is defined and
   passed to another function for filtering output::

       => (setv people [{:name "Alice" :age 20}
       ...             {:name "Bob" :age 25}
       ...             {:name "Charlie" :age 50}
       ...             {:name "Dave" :age 5}])

       => (defn display-people [people filter]
       ...  (for [person people] (if (filter person) (print (:name person)))))

       => (display-people people (fn [person] (< (:age person) 25)))
       Alice
       Dave

   Just as in normal function definitions, if the first element of the
   body is a string, it serves as a docstring. This is useful for giving
   class methods docstrings::

       => (setv times-three
       ...   (fn [x]
       ...    "Multiplies input by three and returns the result."
       ...    (* x 3)))

   This can be confirmed via Python's built-in ``help`` function::

       => (help times-three)
       Help on function times_three:

       times_three(x)
       Multiplies input by three and returns result
       (END)

.. hy:function:: (fn/a [name &rest args])

   ``fn/a`` is a variant of ``fn`` than defines an anonymous coroutine.
   The parameters are similar to ``defn/a``: the first parameter is
   vector of parameters and the rest is the body of the function. ``fn/a`` returns a
   new coroutine.


.. hy:function:: (await [obj])

   ``await`` creates an :ref:`await expression <py:await>`. It takes exactly one
   argument: the object to wait for.


   :strong:`Examples`

   ::

       => (import asyncio)
       => (defn/a main []
       ...    (print "hello")
       ...    (await (asyncio.sleep 1))
       ...    (print "world"))
       => (asyncio.run (main))
       hello
       world

.. hy:function:: break

   ``break`` is used to break out from a loop. It terminates the loop immediately.
   The following example has an infinite ``while`` loop that is terminated as soon
   as the user enters *k*.

   :strong:`Examples`

   ::

     => (while True
     ...   (if (= "k" (input "? "))
     ...       (break)
     ...       (print "Try again")))


.. hy:function:: (cmp [&rest args])

   ``cmp`` creates a :ref:`comparison expression <py:comparisons>`. It isn't
   required for unchained comparisons, which have only one comparison operator,
   nor for chains of the same operator. For those cases, you can use the
   comparison operators directly with Hy's usual prefix syntax, as in ``(= x 1)``
   or ``(< 1 2 3)``. The use of ``cmp`` is to construct chains of heterogeneous
   operators, such as ``x <= y < z``. It uses an infix syntax with the general
   form

   ::

       (cmp ARG OP ARG OP ARG…)

   Hence, ``(cmp x <= y < z)`` is equivalent to ``(and (<= x y) (< y z))``,
   including short-circuiting, except that ``y`` is only evaluated once.

   Each ``ARG`` is an arbitrary form, which does not itself use infix syntax. Use
   :hy:func:`py <py>` if you want fully Python-style operator syntax. You can
   also nest ``cmp`` forms, although this is rarely useful. Each ``OP`` is a
   literal comparison operator; other forms that resolve to a comparison operator
   are not allowed.

   At least two ``ARG``\ s and one ``OP`` are required, and every ``OP`` must be
   followed by an ``ARG``.

   As elsewhere in Hy, the equality operator is spelled ``=``, not ``==`` as in
   Python.


.. hy:function:: continue

   ``continue`` returns execution to the start of a loop. In the following example,
   ``(side-effect1)`` is called for each iteration. ``(side-effect2)``, however,
   is only called on every other value in the list.

   :strong:`Examples`

   ::

       => ;; assuming that (side-effect1) and (side-effect2) are functions and
       => ;; collection is a list of numerical values
       => (for [x collection]
       ...   (side-effect1 x)
       ...   (if (% x 2)
       ...     (continue))
       ...   (side-effect2))

.. hy:function:: (do [&rest body])

   ``do`` (called ``progn`` in some Lisps) takes any number of forms,
   evaluates them, and returns the value of the last one, or ``None`` if no
   forms were provided.

   :strong:`Examples`

   ::

       => (+ 1 (do (setv x (+ 1 1)) x))
       3

.. hy:function:: (for [&rest args])

   ``for`` is used to evaluate some forms for each element in an iterable
   object, such as a list. The return values of the forms are discarded and
   the ``for`` form returns ``None``.

   ::

       => (for [x [1 2 3]]
       ...  (print "iterating")
       ...  (print x))
       iterating
       1
       iterating
       2
       iterating
       3

   In its square-bracketed first argument, ``for`` allows the same types of
   clauses as :hy:macro:`lfor`.

   ::

     => (for [x [1 2 3]  :if (!= x 2)  y [7 8]]
     ...  (print x y))
     1 7
     1 8
     3 7
     3 8

   Furthermore, the last argument of ``for`` can be an ``(else …)`` form.
   This form is executed after the last iteration of the ``for``\'s
   outermost iteration clause, but only if that outermost loop terminates
   normally. If it's jumped out of with e.g. ``break``, the ``else`` is
   ignored.

   ::

       => (for [element [1 2 3]] (if (< element 3)
       ...                             (print element)
       ...                             (break))
       ...    (else (print "loop finished")))
       1
       2

       => (for [element [1 2 3]] (if (< element 4)
       ...                             (print element)
       ...                             (break))
       ...    (else (print "loop finished")))
       1
       2
       3
       loop finished

.. hy:macro:: (lfor [binding iterable &rest body])

   The comprehension forms ``lfor``, :hy:macro:`sfor`, :hy:macro:`dfor`, :hy:macro:`gfor`, and :hy:func:`for`
   are used to produce various kinds of loops, including Python-style
   :ref:`comprehensions <py:comprehensions>`. ``lfor`` in particular
   creates a list comprehension. A simple use of ``lfor`` is::

       => (lfor x (range 5) (* 2 x))
       [0, 2, 4, 6, 8]

   ``x`` is the name of a new variable, which is bound to each element of
   ``(range 5)``. Each such element in turn is used to evaluate the value
   form ``(* 2 x)``, and the results are accumulated into a list.

   Here's a more complex example::

       => (lfor
       ...  x (range 3)
       ...  y (range 3)
       ...  :if (!= x y)
       ...  :setv total (+ x y)
       ...  [x y total])
       [[0, 1, 1], [0, 2, 2], [1, 0, 1], [1, 2, 3], [2, 0, 2], [2, 1, 3]]

   When there are several iteration clauses (here, the pairs of forms ``x
   (range 3)`` and ``y (range 3)``), the result works like a nested loop or
   Cartesian product: all combinations are considered in lexicographic
   order.

   The general form of ``lfor`` is::

       (lfor CLAUSES VALUE)

   where the ``VALUE`` is an arbitrary form that is evaluated to produce
   each element of the result list, and ``CLAUSES`` is any number of
   clauses. There are several types of clauses:

   - Iteration clauses, which look like ``LVALUE ITERABLE``. The ``LVALUE``
     is usually just a symbol, but could be something more complicated,
     like ``[x y]``.
   - ``:async LVALUE ITERABLE``, which is an
     :ref:`asynchronous <py:async for>` form of iteration clause.
   - ``:do FORM``, which simply evaluates the ``FORM``. If you use
     ``(continue)`` or ``(break)`` here, they will apply to the innermost
     iteration clause before the ``:do``.
   - ``:setv LVALUE RVALUE``, which is equivalent to ``:do (setv LVALUE
     RVALUE)``.
   - ``:if CONDITION``, which is equivalent to ``:do (unless CONDITION
     (continue))``.

   For ``lfor``, ``sfor``, ``gfor``, and ``dfor``, variables are scoped as
   if the comprehension form were its own function, so variables defined by
   an iteration clause or ``:setv`` are not visible outside the form. In
   fact, these forms are implemented as generator functions whenever they
   contain Python statements, with the attendant consequences for calling
   ``return``. By contrast, ``for`` shares the caller's scope.

.. hy:macro:: (dfor [binding iterable &rest body])

    ``dfor`` creates a :ref:`dictionary comprehension <py:dict>`. Its syntax
    is the same as that of `:hy:macro:`lfor` except that the final value form must be
    a literal list of two elements, the first of which becomes each key and
    the second of which becomes each value.

    :strong:`Examples`

    ::

        => (dfor x (range 5) [x (* x 10)])
        {0: 0, 1: 10, 2: 20, 3: 30, 4: 40}


.. hy:macro:: (gfor [binding iterable &rest body])

   ``gfor`` creates a :ref:`generator expression <py:genexpr>`. Its syntax
   is the same as that of :hy:macro:`lfor`. The difference is that ``gfor`` returns
   an iterator, which evaluates and yields values one at a time.

   :strong:`Examples`

   ::

       => (setv accum [])
       => (list (take-while
       ...  (fn [x] (< x 5))
       ...  (gfor x (count) :do (.append accum x) x)))
       [0, 1, 2, 3, 4]
       => accum
       [0, 1, 2, 3, 4, 5]

.. hy:macro:: (sfor [binding iterable &rest body])

   ``sfor`` creates a set comprehension. ``(sfor CLAUSES VALUE)`` is
   equivalent to ``(set (lfor CLAUSES VALUE))``. See :hy:macro:`lfor`.

.. hy:function:: (setv [&rest args])

   ``setv`` is used to bind a value, object, or function to a symbol.

   :strong:`Examples`

   ::

       => (setv names ["Alice" "Bob" "Charlie"])
       => (print names)
       [u'Alice', u'Bob', u'Charlie']

       => (setv counter (fn [collection item] (.count collection item)))
       => (counter [1 2 3 4 5 2 3] 2)
       2

   You can provide more than one target–value pair, and the assignments will be made in order::

       => (setv  x 1  y x  x 2)
       => (print x y)
       2 1

   You can perform parallel assignments or unpack the source value with square brackets and :hy:func:`unpack-iterable <unpack-iterable/unpack-mapping>`::

       => (setv duo ["tim" "eric"])
       => (setv [guy1 guy2] duo)
       => (print guy1 guy2)
       tim eric

       => (setv [letter1 letter2 #* others] "abcdefg")
       => (print letter1 letter2 others)
       a b ['c', 'd', 'e', 'f', 'g']


.. hy:function:: (setx [&rest args])

   Whereas ``setv`` creates an assignment statement, ``setx`` creates an assignment expression (see :pep:`572`). It requires Python 3.8 or later. Only one target–value pair is allowed, and the target must be a bare symbol, but the ``setx`` form returns the assigned value instead of ``None``.

   :strong:`Examples`

   ::

       => (when (> (setx x (+ 1 2)) 0)
       ...  (print x "is greater than 0"))
       3 is greater than 0


.. hy:function:: (defclass [class-name super-classes &rest body])

   New classes are declared with ``defclass``. It can take optional parameters in the following order:
   a list defining (a) possible super class(es) and a string (:term:`py:docstring`).

   :strong:`Examples`

   ::

       => (defclass class-name [super-class-1 super-class-2]
       ...   "docstring"
       ...
       ...   (setv attribute1 value1)
       ...   (setv attribute2 value2)
       ...
       ...   (defn method [self] (print "hello!")))

   Both values and functions can be bound on the new class as shown by the example
   below:

   ::

       => (defclass Cat []
       ...  (setv age None)
       ...  (setv colour "white")
       ...
       ...  (defn speak [self] (print "Meow")))

       => (setv spot (Cat))
       => (setv spot.colour "Black")
       'Black'
       => (.speak spot)
       Meow

.. hy:function:: (del [object])

   .. versionadded:: 0.9.12

   ``del`` removes an object from the current namespace.

   :strong:`Examples`

   ::

     => (setv foo 42)
     => (del foo)
     => foo
     Traceback (most recent call last):
       File "<console>", line 1, in <module>
     NameError: name 'foo' is not defined

   ``del`` can also remove objects from mappings, lists, and more.

   ::

     => (setv test (list (range 10)))
     => test
     [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
     => (del (cut test 2 4)) ;; remove items from 2 to 4 excluded
     => test
     [0, 1, 4, 5, 6, 7, 8, 9]
     => (setv dic {"foo" "bar"})
     => dic
     {"foo": "bar"}
     => (del (get dic "foo"))
     => dic
     {}

.. hy:function:: (nonlocal [object])

   .. versionadded:: 0.11.1

   ``nonlocal`` can be used to mark a symbol as not local to the current scope.
   The parameters are the names of symbols to mark as nonlocal.  This is necessary
   to modify variables through nested ``fn`` scopes:

   :strong:`Examples`

   ::

       (defn some-function []
         (setv x 0)
         (register-some-callback
           (fn [stuff]
             (nonlocal x)
             (setv x stuff))))

   Without the call to ``(nonlocal x)``, the inner function would redefine ``x`` to
   ``stuff`` inside its local scope instead of overwriting the ``x`` in the outer
   function.

   See `PEP3104 <https://www.python.org/dev/peps/pep-3104/>`_ for further
   information.

.. hy:function:: (py [string])

   ``py`` parses the given Python code at compile-time and inserts the result into
   the generated abstract syntax tree. Thus, you can mix Python code into a Hy
   program. Only a Python expression is allowed, not statements; use
   :hy:func:`pys <pys>` if you want to use Python statements. The value of the
   expression is returned from the ``py`` form. ::

       (print "A result from Python:" (py "'hello' + 'world'"))

   The code must be given as a single string literal, but you can still use
   macros, :hy:func:`hy.eval <hy.eval>`, and related tools to construct the ``py`` form. If
   having to backslash-escape internal double quotes is getting you down, try a
   :ref:`bracket string <syntax-bracket-strings>`. If you want to evaluate some
   Python code that's only defined at run-time, try the standard Python function
   :func:`eval`.

   Python code need not syntactically round-trip if you use ``hy2py`` on a Hy
   program that uses ``py`` or ``pys``. For example, comments will be removed.


   .. _pys-specialform:

.. hy:function:: (pys [string])

   As :hy:func:`py <py>`, but the code can consist of zero or more statements,
   including compound statements such as ``for`` and ``def``. ``pys`` always
   returns ``None``. Also, the code string is dedented with
   :func:`textwrap.dedent` before parsing, which allows you to intend the code to
   match the surrounding Hy code, but significant leading whitespace in embedded
   string literals will be removed. ::

       (pys "myvar = 5")
       (print "myvar is" myvar)

.. hy:function:: (quasiquote [form])

   ``quasiquote`` allows you to quote a form, but also selectively evaluate
   expressions. Expressions inside a ``quasiquote`` can be selectively evaluated
   using ``unquote`` (``~``). The evaluated form can also be spliced using
   ``unquote-splice`` (``~@``). Quasiquote can be also written using the backquote
   (`````) symbol.

   :strong:`Examples`

   ::

       ;; let `qux' be a variable with value (bar baz)
       `(foo ~qux)
       ; equivalent to '(foo (bar baz))
       `(foo ~@qux)
       ; equivalent to '(foo bar baz)


.. hy:function:: (quote [form])

   ``quote`` returns the form passed to it without evaluating it. ``quote`` can
   alternatively be written using the apostrophe (``'``) symbol.

   :strong:`Examples`

   ::

       => (setv x '(print "Hello World"))
       => x  ; variable x is set to unevaluated expression
       HyExpression([
         HySymbol('print'),
         HyString('Hello World')])
       => (hy.eval x)
       Hello World


.. hy:function:: (require [&rest args])

   ``require`` is used to import macros from one or more given modules. It allows
   parameters in all the same formats as ``import``. The ``require`` form itself
   produces no code in the final program: its effect is purely at compile-time, for
   the benefit of macro expansion. Specifically, ``require`` imports each named
   module and then makes each requested macro available in the current module.

   The following are all equivalent ways to call a macro named ``foo`` in the module ``mymodule``:

   :strong:`Examples`

   ::

       (require mymodule)
       (mymodule.foo 1)

       (require [mymodule :as M])
       (M.foo 1)

       (require [mymodule [foo]])
       (foo 1)

       (require [mymodule [*]])
       (foo 1)

       (require [mymodule [foo :as bar]])
       (bar 1)

   :strong:`Macros that call macros`

   One aspect of ``require`` that may be surprising is what happens when one
   macro's expansion calls another macro. Suppose ``mymodule.hy`` looks like this:

   ::

       (defmacro repexpr [n expr]
         ; Evaluate the expression n times
         ; and collect the results in a list.
         `(list (map (fn [_] ~expr) (range ~n))))

       (defmacro foo [n]
         `(repexpr ~n (input "Gimme some input: ")))

   And then, in your main program, you write:

   ::

       (require [mymodule [foo]])

       (print (mymodule.foo 3))

   Running this raises ``NameError: name 'repexpr' is not defined``, even though
   writing ``(print (foo 3))`` in ``mymodule`` works fine. The trouble is that your
   main program doesn't have the macro ``repexpr`` available, since it wasn't
   imported (and imported under exactly that name, as opposed to a qualified name).
   You could do ``(require [mymodule [*]])`` or ``(require [mymodule [foo
   repexpr]])``, but a less error-prone approach is to change the definition of
   ``foo`` to require whatever sub-macros it needs:

   ::

       (defmacro foo [n]
         `(do
           (require mymodule)
           (mymodule.repexpr ~n (input "Gimme some input: "))))

   It's wise to use ``(require mymodule)`` here rather than ``(require [mymodule
   [repexpr]])`` to avoid accidentally shadowing a function named ``repexpr`` in
   the main program.

   .. note::

      :strong:`Qualified macro names`

      Note that in the current implementation, there's a trick in qualified macro
      names, like ``mymodule.foo`` and ``M.foo`` in the above example. These names
      aren't actually attributes of module objects; they're just identifiers with
      periods in them. In fact, ``mymodule`` and ``M`` aren't defined by these
      ``require`` forms, even at compile-time. None of this will hurt you unless try
      to do introspection of the current module's set of defined macros, which isn't
      really supported anyway.

.. hy:function:: (return [object])

   ``return`` compiles to a :py:keyword:`return` statement. It exits the
   current function, returning its argument if provided with one or
   ``None`` if not.

   :strong:`Examples`

   ::

       => (defn f [x] (for [n (range 10)] (when (> n x) (return n))))
       => (f 3.9)
       4

   Note that in Hy, ``return`` is necessary much less often than in Python,
   since the last form of a function is returned automatically. Hence, an
   explicit ``return`` is only necessary to exit a function early.

   ::

       => (defn f [x] (setv y 10) (+ x y))
       => (f 4)
       14

   To get Python's behavior of returning ``None`` when execution reaches
   the end of a function, put ``None`` there yourself.

   ::

       => (defn f [x] (setv y 10) (+ x y) None)
       => (print (f 4))
       None

.. hy:function:: (cut [coll &optional start stop step])

   ``cut`` can be used to take a subset of a list and create a new list from it.
   The form takes at least one parameter specifying the list to cut. Two
   optional parameters can be used to give the start and end position of the
   subset. If they are not supplied, the default value of ``None`` will be used
   instead. The third optional parameter is used to control step between the elements.

   ``cut`` follows the same rules as its Python counterpart. Negative indices are
   counted starting from the end of the list. Some example usage:

   :strong:`Examples`

   ::

       => (setv collection (range 10))
       => (cut collection)
       [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

       => (cut collection 5)
       [5, 6, 7, 8, 9]

       => (cut collection 2 8)
       [2, 3, 4, 5, 6, 7]

       => (cut collection 2 8 2)
       [2, 4, 6]

       => (cut collection -4 -2)
       [6, 7]

.. hy:function:: (raise [&optional exception])

   The ``raise`` form can be used to raise an ``Exception`` at
   runtime. Example usage:

   :strong:`Examples`

   ::

       (raise)
       ; re-rase the last exception

       (raise IOError)
       ; raise an IOError

       (raise (IOError "foobar"))
       ; raise an IOError("foobar")


   ``raise`` can accept a single argument (an ``Exception`` class or instance)
   or no arguments to re-raise the last ``Exception``.


.. hy:function:: (try [&rest body])

   The ``try`` form is used to catch exceptions (``except``) and run cleanup
   actions (``finally``).

   :strong:`Examples`

   ::

       (try
         (error-prone-function)
         (another-error-prone-function)
         (except [ZeroDivisionError]
           (print "Division by zero"))
         (except [[IndexError KeyboardInterrupt]]
           (print "Index error or Ctrl-C"))
         (except [e ValueError]
           (print "ValueError:" (repr e)))
         (except [e [TabError PermissionError ReferenceError]]
           (print "Some sort of error:" (repr e)))
         (else
           (print "No errors"))
         (finally
           (print "All done")))

   The first argument of ``try`` is its body, which can contain one or more forms.
   Then comes any number of ``except`` clauses, then optionally an ``else``
   clause, then optionally a ``finally`` clause. If an exception is raised with a
   matching ``except`` clause during the execution of the body, that ``except``
   clause will be executed. If no exceptions are raised, the ``else`` clause is
   executed. The ``finally`` clause will be executed last regardless of whether an
   exception was raised.

   The return value of ``try`` is the last form of the ``except`` clause that was
   run, or the last form of ``else`` if no exception was raised, or the ``try``
   body if there is no ``else`` clause.

.. hy:data:: unpack-iterable/unpack-mapping

   (Also known as the splat operator, star operator, argument expansion, argument
   explosion, argument gathering, and varargs, among others...)

   ``unpack-iterable`` and ``unpack-mapping`` allow an iterable or mapping
   object (respectively) to provide positional or keywords arguments
   (respectively) to a function.

   ::

       => (defn f [a b c d] [a b c d])
       => (f (unpack-iterable [1 2]) (unpack-mapping {"c" 3 "d" 4}))
       [1, 2, 3, 4]

   ``unpack-iterable`` is usually written with the shorthand ``#*``, and
   ``unpack-mapping`` with ``#**``.

   ::

       => (f #* [1 2] #** {"c" 3 "d" 4})
       [1, 2, 3, 4]

   Unpacking is allowed in a variety of contexts, and you can unpack
   more than once in one expression (:pep:`3132`, :pep:`448`).

   ::

       => (setv [a #* b c] [1 2 3 4 5])
       => [a b c]
       [1, [2, 3, 4], 5]
       => [#* [1 2] #* [3 4]]
       [1, 2, 3, 4]
       => {#** {1 2} #** {3 4}}
       {1: 2, 3: 4}
       => (f #* [1] #* [2] #** {"c" 3} #** {"d" 4})
       [1, 2, 3, 4]

.. hy:function:: (unquote [symbol])

   Within a quasiquoted form, ``unquote`` forces evaluation of a symbol. ``unquote``
   is aliased to the tilde (``~``) symbol.

   ::

       => (setv nickname "Cuddles")
       => (quasiquote (= nickname (unquote nickname)))
       HyExpression([
         HySymbol('='),
         HySymbol('nickname'),
         'Cuddles'])
       => `(= nickname ~nickname)
       HyExpression([
         HySymbol('='),
         HySymbol('nickname'),
         'Cuddles'])


.. hy:function:: (unquote-splice [symbol])

   ``unquote-splice`` forces the evaluation of a symbol within a quasiquoted form,
   much like ``unquote``. ``unquote-splice`` can be used when the symbol
   being unquoted contains an iterable value, as it "splices" that iterable into
   the quasiquoted form. ``unquote-splice`` can also be used when the value
   evaluates to a false value such as ``None``, ``False``, or ``0``, in which
   case the value is treated as an empty list and thus does not splice anything
   into the form. ``unquote-splice`` is aliased to the ``~@`` syntax.

   ::

       => (setv nums [1 2 3 4])
       => (quasiquote (+ (unquote-splice nums)))
       HyExpression([
         HySymbol('+'),
         1,
         2,
         3,
         4])
       => `(+ ~@nums)
       HyExpression([
         HySymbol('+'),
         1,
         2,
         3,
         4])
       => `[1 2 ~@(if (neg? (first nums)) nums)]
       HyList([
         HyInteger(1),
         HyInteger(2)])

   Here, the last example evaluates to ``('+' 1 2)``, since the condition
   ``(< (nth nums 0) 0)`` is ``False``, which makes this ``if`` expression
   evaluate to ``None``, because the ``if`` expression here does not have an
   else clause. ``unquote-splice`` then evaluates this as an empty value,
   leaving no effects on the list it is enclosed in, therefore resulting in
   ``('+' 1 2)``.

.. hy:function:: (while [condition &rest body])

   ``while`` compiles to a :py:keyword:`while` statement. It is used to execute a
   set of forms as long as a condition is met. The first argument to ``while`` is
   the condition, and any remaining forms constitute the body. The following
   example will output "Hello world!" to the screen indefinitely:

   ::

       (while True (print "Hello world!"))

   The last form of a ``while`` loop can be an ``else`` clause, which is executed
   after the loop terminates, unless it exited abnormally (e.g., with ``break``). So,

   ::

       (setv x 2)
       (while x
          (print "In body")
          (-= x 1)
          (else
            (print "In else")))

   prints

   ::

       In body
       In body
       In else

   If you put a ``break`` or ``continue`` form in the condition of a ``while``
   loop, it will apply to the very same loop rather than an outer loop, even if
   execution is yet to ever reach the loop body. (Hy compiles a ``while`` loop
   with statements in its condition by rewriting it so that the condition is
   actually in the body.) So,

   ::

       (for [x [1]]
          (print "In outer loop")
          (while
            (do
              (print "In condition")
              (break)
              (print "This won't print.")
              True)
            (print "This won't print, either."))
          (print "At end of outer loop"))

   prints

   ::

       In outer loop
       In condition
       At end of outer loop

.. hy:function:: (with-decorator [&rest args])

   ``with-decorator`` is used to wrap a function with another. The function
   performing the decoration should accept a single value: the function being
   decorated, and return a new function. ``with-decorator`` takes a minimum
   of two parameters: the function performing decoration and the function
   being decorated. More than one decorator function can be applied; they
   will be applied in order from outermost to innermost, ie. the first
   decorator will be the outermost one, and so on. Decorators with arguments
   are called just like a function call.

   ::

      (with-decorator decorator-fun
         (defn some-function [] ...)

      (with-decorator decorator1 decorator2 ...
         (defn some-function [] ...)

      (with-decorator (decorator arg) ..
         (defn some-function [] ...)


   In the following example, ``inc-decorator`` is used to decorate the function
   ``addition`` with a function that takes two parameters and calls the
   decorated function with values that are incremented by 1. When
   the decorated ``addition`` is called with values 1 and 1, the end result
   will be 4 (``1+1 + 1+1``).

   ::

       => (defn inc-decorator [func]
       ...  (fn [value-1 value-2] (func (+ value-1 1) (+ value-2 1))))
       => (defn inc2-decorator [func]
       ...  (fn [value-1 value-2] (func (+ value-1 2) (+ value-2 2))))

       => (with-decorator inc-decorator (defn addition [a b] (+ a b)))
       => (addition 1 1)
       4
       => (with-decorator inc2-decorator inc-decorator
       ...  (defn addition [a b] (+ a b)))
       => (addition 1 1)
       8

.. hy:function:: (yield [object])

   ``yield`` is used to create a generator object that returns one or more values.
   The generator is iterable and therefore can be used in loops, list
   comprehensions and other similar constructs.

   The function ``random-numbers`` shows how generators can be used to generate
   infinite series without consuming infinite amount of memory.

   :strong:`Examples`

   ::

       => (defn multiply [bases coefficients]
       ...  (for [(, base coefficient) (zip bases coefficients)]
       ...   (yield (* base coefficient))))

       => (multiply (range 5) (range 5))
       <generator object multiply at 0x978d8ec>

       => (list (multiply (range 10) (range 10)))
       [0, 1, 4, 9, 16, 25, 36, 49, 64, 81]

       => (import random)
       => (defn random-numbers [low high]
       ...  (while True (yield (.randint random low high))))
       => (list (take 15 (random-numbers 1 50)))
       [7, 41, 6, 22, 32, 17, 5, 38, 18, 38, 17, 14, 23, 23, 19]


.. hy:function:: (yield-from [object])

   .. versionadded:: 0.9.13

   ``yield-from`` is used to call a subgenerator.  This is useful if you
   want your coroutine to be able to delegate its processes to another
   coroutine, say, if using something fancy like
   `asyncio <https://docs.python.org/3.4/library/asyncio.html>`_.

Core
----

.. hy:automodule:: hy.core.language
   :members:

.. hy:autofunction:: hy.core.language.calling-module

.. hy:autofunction:: hy.core.language.mangle

.. hy:autofunction:: hy.core.language.unmangle

.. hy:autofunction:: hy.core.language.read-str

.. hy:autofunction:: hy.core.language.read

.. hy:function:: (chain [&rest iters])

   builtin alias for `itertools.chain <https://docs.python.org/3/library/itertools.html#itertools.chain>`_

.. hy:function:: (*map [f iterable])

   builtin alias for `itertools.starmap <https://docs.python.org/3/library/itertools.html#itertools.starmap>`_

.. hy:function:: (compress [data selectors])

   builtin alias for `itertools.compress <https://docs.python.org/3/library/itertools.html#itertools.compress>`_

.. hy:function:: (drop-while [predicate iterable])

   Returns an iterator, skipping members of *coll* until *pred* is ``False``.

   ::

      => (list (drop-while even? [2 4 7 8 9]))
      [7, 8, 9]

      => (list (drop-while numeric? [1 2 3 None "a"])))
      [None, u'a']

      => (list (drop-while pos? [2 4 7 8 9]))
      []

   builtin alias for `itertools.dropwhile <https://docs.python.org/3/library/itertools.html#itertools.dropwhile>`_

.. hy:function:: (filter [pred coll])

   Returns an iterator for all items in *coll* that pass the predicate *pred*.

   See also :hy:func:`remove`.

   ::

      => (list (filter pos? [1 2 3 -4 5 -7]))
      [1, 2, 3, 5]

      => (list (filter even? [1 2 3 -4 5 -7]))
      [2, -4]


.. hy:function:: (group-by [iterable &optional key])

   builtin alias for `itertools.groupby <https://docs.python.org/3/library/itertools.html#itertools.groupby>`_

.. hy:function:: (islice [iterable &rest args])

   Builtin alias for `itertools.islice <https://docs.python.org/3/library/itertools.html#itertools.islice>`_

.. hy:function:: (take-while [predicate iterable])

   Returns an iterator from *coll* as long as *pred* returns ``True``.

   ::

      => (list (take-while pos? [ 1 2 3 -4 5]))
      [1, 2, 3]

      => (list (take-while neg? [ -4 -3 1 2 5]))
      [-4, -3]

      => (list (take-while neg? [ 1 2 3 -4 5]))
      []

   Builtin alias for `itertools.takewhile <https://docs.python.org/3/library/itertools.html#itertools.takewhile>`_

.. hy:function:: (tee [iterable &optional [n 2]])

   Builtin alias for `itertools.tee <https://docs.python.org/3/library/itertools.html#itertools.tee>`_

.. hy:function:: (combinations [iterable r])

   Builtin alias for `itertools.combinations <https://docs.python.org/3/library/itertools.html#itertools.combinations>`_

.. hy:function:: (multicombinations [iterable r])

   Builtin alias for `itertools.combinations_with_replacement <https://docs.python.org/3/library/itertools.html#itertools.combinations_with_replacement>`_

.. hy:function:: (permutations [iterable &optional r])

   Builtin alias for `itertools.permutations <https://docs.python.org/3/library/itertools.html#itertools.permutations>`_

.. hy:function:: (product [&rest args &kwonly [repeat 1]])

   Builtin alias for `itertools.product <https://docs.python.org/3/library/itertools.html#itertools.product>`_

.. hy:function:: (remove [predicate iterable])

   Returns an iterator from *coll* with elements that pass the
   predicate, *pred*, removed.

   See also :ref:`filter`.

   ::

      => (list (remove odd? [1 2 3 4 5 6 7]))
      [2, 4, 6]

      => (list (remove pos? [1 2 3 4 5 6 7]))
      []

      => (list (remove neg? [1 2 3 4 5 6 7]))
      [1, 2, 3, 4, 5, 6, 7]

   Builtin alias for `itertools.filterfalse <https://docs.python.org/3/library/itertools.html#itertools.filterfalse>`_

.. hy:function:: (zip-longest [&rest iterables &kwonly fillvalue])

   Builtin alias for `itertools.zip_longest <https://docs.python.org/3/library/itertools.html#itertools.zip_longest>`_

.. hy:function:: (accumulate [iterable &optional func &kwonly initial])

   Builtin alias for `itertools.accumulate <https://docs.python.org/3/library/itertools.html#itertools.accumulate>`_

.. hy:function:: (count [&optional [start 0] [step 1]])

   Builtin alias for `itertools.count <https://docs.python.org/3/library/itertools.html#itertools.count>`_

.. hy:function:: (cycle [iterable])

   Returns an infinite iterator of the members of coll.

   ::

      => (list (take 7 (cycle [1 2 3])))
      [1, 2, 3, 1, 2, 3, 1]

      => (list (take 2 (cycle [1 2 3])))
      [1, 2]

   Builtin alias for `itertools.cycle <https://docs.python.org/3/library/itertools.html#itertools.cycle>`_

.. hy:function:: (repeat [object &optional times])

   Returns an iterator (infinite) of ``x``.

   ::

      => (list (take 6 (repeat "s")))
      [u's', u's', u's', u's', u's', u's']

   Builtin alias for `itertools.repeat <https://docs.python.org/3/library/itertools.html#itertools.repeat>`_

.. hy:function:: (reduce [function iterable &optional initializer])

   Builtin alias for `functools.reduce <https://docs.python.org/3/library/functools.html#functools.reduce>`_

.. hy:autoclass:: fractions.Fraction
   :members:

.. hy:automodule:: hy.core.shadow
   :members:

.. hy:automodule:: hy.core.bootstrap
   :members:

.. hy:automodule:: hy.core.macros
   :members:
   :macros:
   :tags:

Extra
-----

Anaphoric
*********

.. hy:automodule:: hy.extra.anaphoric
   :members:

Reserved
*********

.. hy:automodule:: hy.extra.reserved
   :members:

Contributor Modules
---------------------

Sequences
*********

.. hy:automodule:: hy.contrib.sequences
   :members:

Walk
****

.. hy:automodule:: hy.contrib.walk
   :members:

Profile
*******

.. hy:automodule:: hy.contrib.profile
   :members:

Loop
****

.. hy:automodule:: hy.contrib.loop
   :members:

Hy Repr
*******

.. hy:automodule:: hy.contrib.hy_repr
   :members:

PPrint
******

.. hy:automodule:: hy.contrib.pprint
   :members:

Destructure
***********

.. hy:automodule:: hy.contrib.destructure
   :members:

Slicing
*******

.. hy:automodule:: hy.contrib.slicing
   :members:
