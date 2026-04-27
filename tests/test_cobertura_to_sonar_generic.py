"""Unit tests for ``scripts/cobertura_to_sonar_generic.py``."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from defusedxml import ElementTree as ET

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "cobertura_to_sonar_generic.py"


def _load_module() -> object:
    """Load the converter as a module object so we can call its functions."""
    spec = importlib.util.spec_from_file_location("cobertura_to_sonar_generic", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


COBERTURA_FIXTURE = """<?xml version="1.0" ?>
<coverage version="7.13.5" timestamp="1" lines-valid="3" lines-covered="2" line-rate="0.6667"
          branches-covered="1" branches-valid="2" branch-rate="0.5" complexity="0">
  <sources><source>.</source></sources>
  <packages>
    <package name="env_inspector_core" line-rate="0.66" branch-rate="0.5" complexity="0">
      <classes>
        <class name="cli.py" filename="env_inspector_core/cli.py"
               complexity="0" line-rate="0.66" branch-rate="0.5">
          <methods/>
          <lines>
            <line number="1" hits="3"/>
            <line number="2" hits="0"/>
            <line number="3" hits="2" branch="true" condition-coverage="50% (1/2)"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
"""


def test_collect_lines_parses_hits_and_branches(tmp_path: Path) -> None:
    """``collect_lines`` returns hits + branch tuples per file/line."""
    module = _load_module()
    cobertura_xml = tmp_path / "coverage.xml"
    cobertura_xml.write_text(COBERTURA_FIXTURE, encoding="utf-8")

    by_file = module.collect_lines(cobertura_xml)

    assert "env_inspector_core/cli.py" in by_file
    rows = by_file["env_inspector_core/cli.py"]
    assert rows[1] == (3, 0, 0)
    assert rows[2] == (0, 0, 0)
    assert rows[3] == (2, 2, 1)


def test_emit_xml_round_trips_through_converter(tmp_path: Path) -> None:
    """``emit_xml`` produces Sonar Generic XML with line + branch attrs."""
    module = _load_module()
    cobertura_xml = tmp_path / "coverage.xml"
    cobertura_xml.write_text(COBERTURA_FIXTURE, encoding="utf-8")
    sonar_xml = tmp_path / "coverage-sonar.xml"

    by_file = module.collect_lines(cobertura_xml)
    file_count = module.emit_xml(by_file, sonar_xml)

    assert file_count == 1
    tree = ET.parse(str(sonar_xml))
    root = tree.getroot()
    assert root.tag == "coverage"
    assert root.get("version") == "1"
    files = root.findall("file")
    assert len(files) == 1
    assert files[0].get("path") == "env_inspector_core/cli.py"

    lines = files[0].findall("lineToCover")
    assert {l.get("lineNumber"): l.get("covered") for l in lines} == {
        "1": "true",
        "2": "false",
        "3": "true",
    }
    # Line 3 has branch coverage info.
    branchy = [l for l in lines if l.get("lineNumber") == "3"][0]
    assert branchy.get("branchesToCover") == "2"
    assert branchy.get("coveredBranches") == "1"


def test_collect_lines_skips_class_without_filename(tmp_path: Path) -> None:
    """Cobertura ``<class>`` elements without a ``filename`` attribute are ignored."""
    module = _load_module()
    cobertura_xml = tmp_path / "coverage.xml"
    cobertura_xml.write_text(
        """<?xml version="1.0" ?>
<coverage version="7.13.5">
  <sources><source>.</source></sources>
  <packages>
    <package name="pkg">
      <classes>
        <class name="anon">
          <methods/>
          <lines><line number="1" hits="1"/></lines>
        </class>
        <class name="real" filename="real.py">
          <methods/>
          <lines><line number="1" hits="1"/></lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
""",
        encoding="utf-8",
    )

    by_file = module.collect_lines(cobertura_xml)
    assert list(by_file) == ["real.py"]


def test_summarise_returns_total_and_covered(tmp_path: Path) -> None:
    """``summarise`` reports total lines and the covered subset."""
    module = _load_module()
    by_file = {
        "a.py": {1: (1, 0, 0), 2: (0, 0, 0), 3: (5, 0, 0)},
        "b.py": {10: (2, 0, 0)},
    }
    total, covered = module.summarise(by_file)
    assert total == 4
    assert covered == 3


def test_main_writes_xml_and_returns_zero(tmp_path: Path, capsys, monkeypatch) -> None:
    """``main`` reads --in, writes --out, and returns 0 on success."""
    module = _load_module()
    cobertura_xml = tmp_path / "coverage.xml"
    cobertura_xml.write_text(COBERTURA_FIXTURE, encoding="utf-8")
    sonar_xml = tmp_path / "coverage-sonar.xml"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cobertura_to_sonar_generic.py",
            "--in",
            str(cobertura_xml),
            "--out",
            str(sonar_xml),
        ],
    )

    rc = module.main()
    captured = capsys.readouterr()
    assert rc == 0
    assert "1 files" in captured.out
    assert "lines 2/3" in captured.out
    assert sonar_xml.exists()
