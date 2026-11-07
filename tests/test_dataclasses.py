"""Tests for the Python 3.6 dataclasses fallback."""

import pytest

from pycert._dataclasses import FrozenInstanceError, dataclass, field


def test_basic_defaults_and_positional():
    @dataclass
    class Point:
        x: int
        y: int = 2

    assert Point(1).x == 1 and Point(1).y == 2
    assert Point(1, 3).y == 3
    assert Point(y=9, x=8).x == 8


def test_default_factory_per_instance():
    @dataclass
    class Bag:
        items: "list[int]" = field(default_factory=list)

    first, second = Bag(), Bag()
    first.items.append(1)
    assert second.items == []


def test_missing_argument():
    @dataclass
    class Required:
        value: int

    with pytest.raises(TypeError, match="missing required"):
        Required()


def test_too_many_arguments():
    @dataclass
    class One:
        value: int

    with pytest.raises(TypeError, match="positional"):
        One(1, 2)


def test_unexpected_keyword():
    @dataclass
    class One:
        value: int

    with pytest.raises(TypeError, match="unexpected keyword"):
        One(value=1, other=2)


def test_mutable_defaults_are_refused():
    with pytest.raises(ValueError):

        @dataclass
        class Bad:
            items: list = field(default=[])

    with pytest.raises(ValueError):
        field(default_factory=42)


def test_default_and_factory_together():
    with pytest.raises(ValueError):
        field(default=1, default_factory=list)


def test_repr_and_eq():
    @dataclass
    class Item:
        name: str
        count: int = 0

    assert repr(Item("x")) == "Item(name='x', count=0)"
    assert Item("x") == Item("x", 0)
    assert Item("x") != Item("y")
    assert Item("x") != "x"


def test_repr_false_and_compare_false():
    @dataclass
    class Item:
        visible: int
        hidden: int = field(default=0, repr=False, compare=False)

    assert "hidden" not in repr(Item(1, 2))
    assert Item(1, 2) == Item(1, 99)


def test_init_false():
    @dataclass
    class Item:
        value: int
        computed: int = field(default=7, init=False)

    item = Item(1)
    assert item.computed == 7
    with pytest.raises(TypeError, match="unexpected keyword"):
        Item(1, computed=2)


def test_frozen():
    @dataclass(frozen=True)
    class Frozen:
        value: int

    item = Frozen(1)
    with pytest.raises(FrozenInstanceError):
        item.value = 2
    with pytest.raises(FrozenInstanceError):
        del item.value
    assert hash(item) == hash(Frozen(1))
    assert item == Frozen(1)


def test_inheritance():
    @dataclass
    class Base:
        a: int
        b: int = 2

    @dataclass
    class Child(Base):
        c: int = 3

    child = Child(1, 2, 4)
    assert (child.a, child.b, child.c) == (1, 2, 4)
    assert repr(child) == "Child(a=1, b=2, c=4)"


def test_unsupported_options():
    with pytest.raises(NotImplementedError):
        dataclass(order=True)
    with pytest.raises(NotImplementedError):
        dataclass(unsafe_hash=True)


def test_empty_class():
    @dataclass
    class Empty:
        pass

    assert repr(Empty()) == "Empty()"
    assert Empty() == Empty()


def test_nested_repr():
    @dataclass
    class Inner:
        value: int

    @dataclass
    class Outer:
        inner: Inner

    assert repr(Outer(Inner(1))) == "Outer(inner=Inner(value=1))"
