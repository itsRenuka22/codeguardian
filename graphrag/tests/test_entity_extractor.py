import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from entity_extractor import EntityExtractor

extractor = EntityExtractor()


def test_php_sql_injection():
    code = '$id = $_GET["id"]; mysqli_query($conn, $query);'
    funcs = extractor.extract_functions(code, "php")
    sources = extractor.extract_sources(code, "php")
    assert "mysqli_query" in funcs
    assert any("GET" in s for s in sources)


def test_php_command_injection():
    code = 'system("ping " . $_POST["host"]);'
    funcs = extractor.extract_functions(code, "php")
    sources = extractor.extract_sources(code, "php")
    assert "system" in funcs
    assert any("POST" in s for s in sources)


def test_java_sql_injection():
    code = 'String id = request.getParameter("id"); stmt.executeQuery(sql);'
    funcs = extractor.extract_functions(code, "java")
    sources = extractor.extract_sources(code, "java")
    assert "executeQuery" in funcs
    assert any("getParameter" in s for s in sources)


def test_python_code_injection():
    code = 'user_input = request.args.get("cmd"); eval(user_input)'
    funcs = extractor.extract_functions(code, "python")
    sources = extractor.extract_sources(code, "python")
    assert "eval" in funcs
    assert any("args" in s for s in sources)


def test_ruby_command_injection():
    code = 'system(params[:cmd])'
    funcs = extractor.extract_functions(code, "ruby")
    sources = extractor.extract_sources(code, "ruby")
    assert "system" in funcs
    assert any("params" in s for s in sources)


def test_no_functions_found():
    code = "x = 1 + 2"
    funcs = extractor.extract_functions(code, "python")
    assert funcs == []


def test_empty_code():
    result = extractor.extract_entities({"item_id": "test", "code": "", "language": "php"})
    assert result["functions"] == []
    assert result["sources"] == []


def test_malformed_code_no_crash():
    code = "<?php $$$invalid === )));"
    try:
        extractor.extract_functions(code, "php")
        extractor.extract_sources(code, "php")
    except Exception as e:
        pytest.fail(f"Crashed on malformed code: {e}")


def test_comments_ignored():
    code = "# eval(user_input)\nresult = 1 + 1"
    funcs = extractor.extract_functions(code, "python")
    assert "eval" not in funcs


def test_extract_entities_structure():
    item = {"item_id": "code_001", "code": "$id = $_GET['id']; echo $id;", "language": "php"}
    result = extractor.extract_entities(item)
    assert "code_id" in result
    assert "functions" in result
    assert "sources" in result
    assert "language" in result
    assert result["code_id"] == "code_001"
