"""Tests for the npm and PyPI manifest parsers."""

import json

import pytest

from app.parsers import available_ecosystems, get_parser
from app.parsers.base import ParseError
from app.parsers.npm import NpmParser
from app.parsers.pypi import PypiParser


def _by_name(packages):
    return {pkg.name: pkg for pkg in packages}


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


def test_parsers_register_themselves():
    assert "npm" in available_ecosystems()
    assert "PyPI" in available_ecosystems()
    assert isinstance(get_parser("npm"), NpmParser)
    assert isinstance(get_parser("PyPI"), PypiParser)


# --------------------------------------------------------------------------- #
# npm
# --------------------------------------------------------------------------- #


def test_npm_normal_and_semver_prefixes():
    content = json.dumps(
        {
            "dependencies": {
                "express": "4.18.2",  # exact
                "lodash": "^4.17.21",  # caret
                "react": "~18.2.0",  # tilde
                "axios": ">=1.4.0",  # single comparator -> strip to concrete
                "chalk": "=5.3.0",  # equals
                "next": "v13.4.1",  # v-prefixed
            }
        }
    )
    pkgs = _by_name(NpmParser().parse(content))

    assert pkgs["express"].version == "4.18.2"
    assert pkgs["lodash"].version == "4.17.21"
    assert pkgs["react"].version == "18.2.0"
    assert pkgs["axios"].version == "1.4.0"
    assert pkgs["chalk"].version == "5.3.0"
    assert pkgs["next"].version == "13.4.1"
    # `dependencies` are direct.
    assert all(pkg.is_direct for pkg in pkgs.values())


def test_npm_dev_vs_direct_distinction():
    content = json.dumps(
        {
            "dependencies": {"express": "4.18.2"},
            "devDependencies": {"jest": "29.7.0"},
        }
    )
    pkgs = _by_name(NpmParser().parse(content))

    assert pkgs["express"].is_direct is True
    assert pkgs["jest"].is_direct is False


def test_npm_prerelease_and_build_metadata_are_concrete():
    content = json.dumps({"dependencies": {"foo": "^1.2.3-beta.1", "bar": "2.0.0+build.7"}})
    pkgs = _by_name(NpmParser().parse(content))

    assert pkgs["foo"].version == "1.2.3-beta.1"
    assert pkgs["bar"].version == "2.0.0+build.7"


@pytest.mark.parametrize(
    "spec",
    [
        ">=1.0.0 <2.0.0",  # compound range
        "1.x",  # wildcard
        "1.2.*",  # wildcard
        "*",  # any
        "latest",  # dist-tag
        "^1.0.0 || ^2.0.0",  # OR range
        "1.0.0 - 2.0.0",  # hyphen range
        "git+https://github.com/u/r.git",  # git ref
        "github:user/repo",  # shorthand git ref
        "file:../local-pkg",  # local path
        "workspace:*",  # workspace protocol
        "npm:other-pkg@^1.0.0",  # aliased
    ],
)
def test_npm_unpinned_and_ranges_are_flagged(spec):
    content = json.dumps({"dependencies": {"pkg": spec}})
    (pkg,) = NpmParser().parse(content)
    # Flagged: the version is left as the raw, unresolvable spec string so
    # downstream skips it. The package is still emitted.
    assert pkg.name == "pkg"
    assert pkg.version == spec
    assert pkg.is_direct is True


def test_npm_no_dependency_sections():
    assert NpmParser().parse(json.dumps({"name": "app", "version": "1.0.0"})) == []


def test_npm_malformed_json_raises_parse_error():
    with pytest.raises(ParseError):
        NpmParser().parse("{ this is not json ")


def test_npm_non_object_root_raises_parse_error():
    with pytest.raises(ParseError):
        NpmParser().parse("[1, 2, 3]")


def test_npm_non_object_dependencies_raises_parse_error():
    with pytest.raises(ParseError):
        NpmParser().parse(json.dumps({"dependencies": "oops"}))


# --------------------------------------------------------------------------- #
# PyPI
# --------------------------------------------------------------------------- #


def test_pypi_normal_pins_and_operators():
    content = "\n".join(
        [
            "flask==2.0.1",
            "requests===2.31.0",  # arbitrary-equality, still a single pin
        ]
    )
    pkgs = _by_name(PypiParser().parse(content))

    assert pkgs["flask"].version == "2.0.1"
    assert pkgs["requests"].version == "2.31.0"
    assert all(pkg.is_direct for pkg in pkgs.values())


def test_pypi_comments_blank_lines_and_includes():
    content = "\n".join(
        [
            "# a full-line comment",
            "",
            "   ",
            "django==4.2  # inline comment",
            "-r other-requirements.txt",  # include: skipped, not recursed
            "-c constraints.txt",  # constraint include: skipped
            "--index-url https://example.com/simple",  # option line: skipped
            "celery==5.3.6",
        ]
    )
    pkgs = _by_name(PypiParser().parse(content))

    assert set(pkgs) == {"django", "celery"}
    assert pkgs["django"].version == "4.2"
    assert pkgs["celery"].version == "5.3.6"


def test_pypi_environment_markers_are_handled():
    content = 'importlib-metadata==6.0.0; python_version < "3.8"'
    (pkg,) = PypiParser().parse(content)

    # The marker is parsed (no crash) and the package is still emitted.
    assert pkg.name == "importlib-metadata"
    assert pkg.version == "6.0.0"


def test_pypi_name_uses_pypi_normalized_casing():
    content = "Flask_Caching.Extra==1.0.0"
    (pkg,) = PypiParser().parse(content)

    # PEP 503 normalization: lowercased, runs of [-_.] collapsed to a single '-'.
    assert pkg.name == "flask-caching-extra"


@pytest.mark.parametrize(
    "line,expected_version",
    [
        ("urllib3>=1.26", ">=1.26"),  # open range
        ("numpy~=1.24.0", "~=1.24.0"),  # compatible release
        ("scipy>=1.0,<2.0", "<2.0,>=1.0"),  # bounded range (normalized order)
        ("pandas==2.0.*", "==2.0.*"),  # wildcard pin
        ("rich", "*"),  # unpinned
    ],
)
def test_pypi_ranges_and_unpinned_are_flagged(line, expected_version):
    (pkg,) = PypiParser().parse(line)
    # Flagged: version holds the raw specifier (or '*' when unpinned); the
    # package is still emitted so it shows up in inventory.
    assert pkg.version == expected_version


def test_pypi_malformed_requirement_raises_parse_error():
    with pytest.raises(ParseError):
        PypiParser().parse("this is === not a valid requirement!!!")
