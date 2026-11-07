"""Minimal ``dataclasses`` fallback for Python 3.6.

pyCert uses a small, well-defined subset of :mod:`dataclasses`: ordered fields
with defaults and ``default_factory``, ``frozen``, ``repr``/``eq`` and
inheritance.  This module implements exactly that, and nothing else, so the
behaviour is predictable on 3.6 and testable everywhere (the test suite uses it
directly even on newer interpreters).

Unsupported features raise ``NotImplementedError`` instead of silently doing the
wrong thing: ``order``, ``unsafe_hash``, ``kw_only``, ``InitVar``,
``asdict``/``astuple``/``replace``.
"""

from typing import Any, Dict, List, Tuple

__all__ = ["dataclass", "field", "Field", "FrozenInstanceError"]


class FrozenInstanceError(AttributeError):
    pass


class _Missing:
    def __repr__(self) -> str:
        return "<missing>"


_MISSING = _Missing()
_MUTABLE_TYPES = (list, dict, set)


class Field:
    __slots__ = ("default", "default_factory", "init", "repr", "compare")

    def __init__(
        self,
        default: Any = _MISSING,
        default_factory: Any = _MISSING,
        init: bool = True,
        repr: bool = True,
        compare: bool = True,
    ) -> None:
        if default is not _MISSING and default_factory is not _MISSING:
            raise ValueError("cannot specify both default and default_factory")
        if default is not _MISSING and isinstance(default, _MUTABLE_TYPES):
            raise ValueError("mutable default; use default_factory")
        if default_factory is not _MISSING and not callable(default_factory):
            raise ValueError("default_factory must be callable")
        self.default = default
        self.default_factory = default_factory
        self.init = init
        self.repr = repr
        self.compare = compare


def field(
    *,
    default: Any = _MISSING,
    default_factory: Any = _MISSING,
    init: bool = True,
    repr: bool = True,
    compare: bool = True,
) -> Field:
    return Field(default, default_factory, init, repr, compare)


def _collect_fields(cls) -> List[Tuple[str, Any]]:
    fields: List[Tuple[str, Any]] = []
    seen = set()
    for base in reversed(cls.__mro__[1:-1]):
        for name in getattr(base, "__annotations__", {}):
            default = base.__dict__.get(name, _MISSING)
            if name in seen:
                fields = [(n, d) for n, d in fields if n != name]
            fields.append((name, default))
            seen.add(name)
    for name in getattr(cls, "__annotations__", {}):
        default = cls.__dict__.get(name, _MISSING)
        if name in seen:
            fields = [(n, d) for n, d in fields if n != name]
        fields.append((name, default))
        seen.add(name)
    return fields


def _default_for(cls, name: str, default: Any) -> Any:
    if isinstance(default, Field):
        if default.default_factory is not _MISSING:
            return default.default_factory()
        if default.default is not _MISSING:
            return default.default
    elif default is not _MISSING:
        return default
    raise TypeError("%s() missing required argument: %r" % (cls.__name__, name))


def _make_init(cls, fields, frozen: bool):
    init_fields = [
        (name, default) for name, default in fields if not isinstance(default, Field) or default.init
    ]

    def __init__(self, *args, **kwargs):
        if frozen:
            object.__setattr__(self, "_pycert_frozen", False)
        if len(args) > len(init_fields):
            raise TypeError(
                "%s() takes %d positional arguments but %d were given"
                % (cls.__name__, len(init_fields), len(args))
            )
        values: Dict[str, Any] = {}
        for (name, _default), value in zip(init_fields, args):
            values[name] = value
        for name, _default in init_fields[len(args) :]:
            if name in kwargs:
                values[name] = kwargs.pop(name)
        if kwargs:
            unexpected = next(iter(kwargs))
            raise TypeError("%s() got an unexpected keyword argument %r" % (cls.__name__, unexpected))
        for name, default in fields:
            if isinstance(default, Field) and not default.init:
                value = _default_for(cls, name, default)
            elif name in values:
                value = values[name]
            else:
                value = _default_for(cls, name, default)
            object.__setattr__(self, name, value)
        if frozen:
            object.__setattr__(self, "_pycert_frozen", True)

    return __init__


def _make_repr(cls, fields):
    repr_fields = [name for name, default in fields if not isinstance(default, Field) or default.repr]

    def __repr__(self):
        parts = ["%s=%r" % (name, getattr(self, name, None)) for name in repr_fields]
        return "%s(%s)" % (cls.__name__, ", ".join(parts))

    return __repr__


def _make_eq(cls, fields):
    compare_fields = [name for name, default in fields if not isinstance(default, Field) or default.compare]

    def __eq__(self, other):
        if other.__class__ is not self.__class__:
            return NotImplemented
        return all(getattr(self, name, None) == getattr(other, name, None) for name in compare_fields)

    def __ne__(self, other):
        result = __eq__(self, other)
        return result if result is NotImplemented else not result

    return __eq__, __ne__


def dataclass(
    _cls=None,
    *,
    init: bool = True,
    repr: bool = True,
    eq: bool = True,
    order: bool = False,
    unsafe_hash: bool = False,
    frozen: bool = False,
):
    if order:
        raise NotImplementedError("dataclass(order=True) is not supported on Python 3.6")
    if unsafe_hash:
        raise NotImplementedError("dataclass(unsafe_hash=True) is not supported on Python 3.6")

    def wrap(cls):
        fields = _collect_fields(cls)
        cls.__pycert_fields__ = fields
        if init:
            cls.__init__ = _make_init(cls, fields, frozen)
        if repr:
            cls.__repr__ = _make_repr(cls, fields)
        if eq:
            cls.__eq__, cls.__ne__ = _make_eq(cls, fields)
        if frozen:
            cls.__hash__ = lambda self: hash(tuple(getattr(self, n) for n, _ in fields))

            def __setattr__(self, name, value):
                if getattr(self, "_pycert_frozen", False):
                    raise FrozenInstanceError("cannot assign to field %r" % name)
                object.__setattr__(self, name, value)

            def __delattr__(self, name):
                if getattr(self, "_pycert_frozen", False):
                    raise FrozenInstanceError("cannot delete field %r" % name)
                object.__delattr__(self, name)

            cls.__setattr__ = __setattr__
            cls.__delattr__ = __delattr__
        return cls

    return wrap(_cls) if _cls is not None else wrap
