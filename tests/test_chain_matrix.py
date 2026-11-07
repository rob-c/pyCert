"""Chain-building matrix for keys, extensions, validity and anchors."""

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pycert import certs, chain
from pycert.errors import ChainError


def key(kind):
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kind == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    raise AssertionError(kind)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(
    cn,
    *,
    issuer=None,
    issuer_key=None,
    public_key=None,
    ca=True,
    path_length=None,
    days_before=1,
    days_after=365,
    ski=True,
    aki=None,
    hash_algorithm=None,
    san=None,
    constraints=None,
    basic=True,
):
    subject = name(cn)
    issuer_name = issuer.subject if issuer is not None else subject
    signer_key = issuer_key if issuer_key is not None else public_key
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=days_before))
        .not_valid_after(now + dt.timedelta(days=days_after))
    )
    if basic:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
    if ski:
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    if aki is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(aki), critical=False
        )
    if san is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(value) for value in san]), critical=False
        )
    if constraints is not None:
        builder = builder.add_extension(constraints, critical=True)
    return builder.sign(signer_key, hash_algorithm or hashes.SHA256())


def hierarchy(issuer_kind="ec", leaf_kind="ec", hash_algorithm=None):
    root_key = key(issuer_kind)
    root = issue(
        "matrix root",
        public_key=root_key.public_key(),
        issuer_key=root_key,
        path_length=1,
        days_after=3650,
        hash_algorithm=hash_algorithm,
    )
    intermediate_key = key(issuer_kind)
    intermediate = issue(
        "matrix intermediate",
        issuer=root,
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        path_length=0,
        aki=root_key.public_key(),
        hash_algorithm=hash_algorithm,
    )
    leaf_key = key(leaf_kind)
    leaf = issue(
        "leaf.example.org",
        issuer=intermediate,
        issuer_key=intermediate_key,
        public_key=leaf_key.public_key(),
        ca=False,
        aki=intermediate_key.public_key(),
        san=["leaf.example.org"],
        hash_algorithm=hash_algorithm,
    )
    return root_key, root, intermediate_key, intermediate, leaf_key, leaf


@pytest.mark.parametrize("issuer_kind", ["ec", "rsa"])
@pytest.mark.parametrize("leaf_kind", ["ec", "rsa"])
@pytest.mark.parametrize("hash_name", ["sha256", "sha384"])
def test_key_and_hash_matrix(issuer_kind, leaf_kind, hash_name):
    algorithm = hashes.SHA256() if hash_name == "sha256" else hashes.SHA384()
    _, root, _, intermediate, _, leaf = hierarchy(issuer_kind, leaf_kind, algorithm)
    result = chain.build_chain(leaf, anchors=[root], extra=[intermediate])
    assert result.trusted
    assert result.complete
    assert [certs.common_name(c.subject) for c in result.chain] == [
        "leaf.example.org",
        "matrix intermediate",
        "matrix root",
    ]


@pytest.mark.parametrize(
    "leaf_ski,leaf_aki,intermediate_ski,expected",
    [
        (True, True, True, True),
        (True, False, True, True),
        (False, True, True, True),
        (True, True, False, True),
    ],
)
def test_ski_aki_matrix(leaf_ski, leaf_aki, intermediate_ski, expected):
    root_key = key("ec")
    root = issue("root", issuer_key=root_key, public_key=root_key.public_key(), path_length=1)
    intermediate_key = key("ec")
    intermediate = issue(
        "intermediate",
        issuer=root,
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        path_length=0,
        ski=intermediate_ski,
        aki=root_key.public_key(),
    )
    leaf_key = key("ec")
    leaf = issue(
        "leaf",
        issuer=intermediate,
        issuer_key=intermediate_key,
        public_key=leaf_key.public_key(),
        ca=False,
        ski=leaf_ski,
        aki=intermediate_key.public_key() if leaf_aki else None,
    )
    assert chain.build_chain(leaf, anchors=[root], extra=[intermediate]).trusted is expected


def test_mismatched_aki_is_rejected():
    root_key = key("ec")
    root = issue("root", issuer_key=root_key, public_key=root_key.public_key(), path_length=1)
    intermediate_key = key("ec")
    # Give the intermediate a SubjectKeyIdentifier that does not match the
    # leaf's AuthorityKeyIdentifier.
    wrong_ski_key = key("ec")
    intermediate = issue(
        "intermediate",
        issuer=root,
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        path_length=0,
        aki=root_key.public_key(),
    )
    leaf_key = key("ec")
    leaf = issue(
        "leaf",
        issuer=intermediate,
        issuer_key=intermediate_key,
        public_key=leaf_key.public_key(),
        ca=False,
        aki=wrong_ski_key.public_key(),
    )
    result = chain.build_chain(leaf, anchors=[root], extra=[intermediate])
    assert not result.trusted
    assert any("no issuer" in problem for problem in result.problems)


@pytest.mark.parametrize("basic,ca", [(True, True), (True, False), (False, True)])
def test_basic_constraints_matrix(basic, ca):
    root_key = key("ec")
    root = issue("root", issuer_key=root_key, public_key=root_key.public_key(), path_length=1)
    intermediate_key = key("ec")
    intermediate = issue(
        "intermediate",
        issuer=root,
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        basic=basic,
        ca=ca,
        aki=root_key.public_key(),
    )
    leaf_key = key("ec")
    leaf = issue(
        "leaf",
        issuer=intermediate,
        issuer_key=intermediate_key,
        public_key=leaf_key.public_key(),
        ca=False,
        aki=intermediate_key.public_key(),
    )
    result = chain.build_chain(leaf, anchors=[root], extra=[intermediate])
    assert result.trusted is (ca or not basic)


@pytest.mark.parametrize(
    "leaf_before,leaf_after,issuer_before,issuer_after,trusted",
    [
        (1, 30, 1, 30, True),
        (30, -1, 1, 30, False),  # leaf expired yesterday
        (30, -1, 30, -1, False),  # leaf and issuer expired
        (1, 30, 30, -1, False),  # issuer expired
        (-10, 30, 1, 30, False),  # leaf not valid yet
    ],
)
def test_validity_matrix(leaf_before, leaf_after, issuer_before, issuer_after, trusted):
    root_key = key("ec")
    root = issue("root", issuer_key=root_key, public_key=root_key.public_key(), path_length=1)
    intermediate_key = key("ec")
    intermediate = issue(
        "intermediate",
        issuer=root,
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        path_length=0,
        aki=root_key.public_key(),
        days_before=issuer_before,
        days_after=issuer_after,
    )
    leaf_key = key("ec")
    leaf = issue(
        "leaf",
        issuer=intermediate,
        issuer_key=intermediate_key,
        public_key=leaf_key.public_key(),
        ca=False,
        aki=intermediate_key.public_key(),
        days_before=leaf_before,
        days_after=leaf_after,
    )
    assert chain.build_chain(leaf, anchors=[root], extra=[intermediate]).trusted is trusted


def test_expired_root_anchor_is_still_trusted():
    root_key = key("ec")
    root = issue(
        "root",
        issuer_key=root_key,
        public_key=root_key.public_key(),
        path_length=1,
        days_before=100,
        days_after=-10,
    )
    intermediate_key = key("ec")
    intermediate = issue(
        "intermediate",
        issuer=root,
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        path_length=0,
        aki=root_key.public_key(),
    )
    leaf_key = key("ec")
    leaf = issue(
        "leaf",
        issuer=intermediate,
        issuer_key=intermediate_key,
        public_key=leaf_key.public_key(),
        ca=False,
        aki=intermediate_key.public_key(),
    )
    result = chain.build_chain(leaf, anchors=[root], extra=[intermediate])
    assert result.trusted


@pytest.mark.parametrize("anchor", ["root", "intermediate", "leaf", "unrelated"])
def test_anchor_matrix(anchor):
    root_key, root, intermediate_key, intermediate, leaf_key, leaf = hierarchy()
    unrelated_key = key("ec")
    unrelated = issue("unrelated", issuer_key=unrelated_key, public_key=unrelated_key.public_key())
    anchors = {
        "root": [root],
        "intermediate": [intermediate],
        "leaf": [leaf],
        "unrelated": [unrelated],
    }[anchor]
    result = chain.build_chain(leaf, anchors=anchors, extra=[root, intermediate])
    assert result.trusted is (anchor in ("root", "intermediate", "leaf"))


def test_deep_chain_hits_the_depth_limit():
    root_key = key("ec")
    root = issue("root", issuer_key=root_key, public_key=root_key.public_key(), path_length=20)
    pool = [root]
    current = root
    current_key = root_key
    for index in range(12):
        next_key = key("ec")
        current = issue(
            "ca-%d" % index,
            issuer=current,
            issuer_key=current_key,
            public_key=next_key.public_key(),
            path_length=20,
            aki=current_key.public_key(),
        )
        pool.append(current)
        current_key = next_key
    leaf_key = key("ec")
    leaf = issue(
        "leaf",
        issuer=current,
        issuer_key=current_key,
        public_key=leaf_key.public_key(),
        ca=False,
        aki=current_key.public_key(),
    )
    result = chain.build_chain(leaf, anchors=[root], extra=pool)
    assert not result.trusted
    assert any("longer than" in problem for problem in result.problems)


def test_name_constraints_allow_matching_san():
    root_key = key("ec")
    root = issue("root", issuer_key=root_key, public_key=root_key.public_key(), path_length=1)
    intermediate_key = key("ec")
    intermediate = issue(
        "intermediate",
        issuer=root,
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        path_length=0,
        aki=root_key.public_key(),
        constraints=x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("example.org")], excluded_subtrees=None
        ),
    )
    leaf_key = key("ec")
    leaf = issue(
        "leaf",
        issuer=intermediate,
        issuer_key=intermediate_key,
        public_key=leaf_key.public_key(),
        ca=False,
        aki=intermediate_key.public_key(),
        san=["host.example.org"],
    )
    result = chain.build_chain(leaf, anchors=[root], extra=[intermediate])
    assert result.trusted is True


def test_name_constraint_violation_is_reported():
    root_key = key("ec")
    root = issue("root", issuer_key=root_key, public_key=root_key.public_key(), path_length=1)
    intermediate_key = key("ec")
    intermediate = issue(
        "intermediate",
        issuer=root,
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        path_length=0,
        aki=root_key.public_key(),
        constraints=x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("other.org")], excluded_subtrees=None
        ),
    )
    leaf_key = key("ec")
    leaf = issue(
        "leaf",
        issuer=intermediate,
        issuer_key=intermediate_key,
        public_key=leaf_key.public_key(),
        ca=False,
        aki=intermediate_key.public_key(),
        san=["host.example.org"],
    )
    result = chain.build_chain(leaf, anchors=[root], extra=[intermediate])
    assert not result.trusted
    assert any("outside permitted" in problem for problem in result.problems)


def test_duplicate_certificates_are_deduplicated():
    _, root, _, intermediate, _, leaf = hierarchy()
    result = chain.build_chain(leaf, anchors=[root, root], extra=[intermediate, intermediate, leaf])
    assert result.trusted
    assert len(result.chain) == 3


def test_chain_result_helpers():
    _, root, _, intermediate, _, leaf = hierarchy()
    result = chain.build_chain(leaf, anchors=[root], extra=[intermediate])
    assert "BEGIN CERTIFICATE" in result.pem()
    assert result.leaf is leaf
    assert result.issuers == [intermediate, root]
    payload = result.as_dict()
    assert payload["trusted"] is True
    assert len(payload["chain"]) == 3
    result.require_valid()


def test_require_valid_raises_for_untrusted():
    _, _root, _, intermediate, _, leaf = hierarchy()
    result = chain.build_chain(leaf, anchors=[], extra=[intermediate])
    with pytest.raises(ChainError):
        result.require_valid()


def test_system_anchors_are_available():
    anchors = chain.system_anchors()
    assert isinstance(anchors, list)
    assert anchors
    assert all(isinstance(c, x509.Certificate) for c in anchors[:5])
