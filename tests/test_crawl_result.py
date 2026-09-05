import json
from pathlib import Path

from torbot.crawl_result import CrawlResultAdapter, invalid_result
from torbot.modules.linktree import LinkNode, LinkTree


class EmptyClient:
    pass


def make_tree() -> LinkTree:
    tree = LinkTree("https://EXAMPLE.com", depth=1, client=EmptyClient())
    root = LinkNode("Root", "https://example.com/", 200, "", 0.0, [], [])
    child = LinkNode(
        "Child", "https://example.com/child", 200, "", 0.0,
        ["+14155551234"], ["info@example.com"],
    )
    tree.create_node(root.tag, root.identifier, data=root)
    tree.create_node(child.tag, child.identifier, parent=root.identifier, data=child)
    return tree


def test_shared_contract_matches_gotor_baseline_fixture():
    gotor = json.loads(
        (Path(__file__).parent / "fixtures" / "gotor-v1-success.json").read_text()
    )
    result = CrawlResultAdapter(make_tree(), uses_tor=False).result(run_id="run-1")

    assert result["schemaVersion"] == gotor["schemaVersion"]
    assert result["target"] == gotor["target"]
    assert result["settings"]["maxDepth"] == gotor["maxDepth"]
    assert result["settings"]["usesTor"] == gotor["usesTor"]
    assert result["pages"][0]["url"] == gotor["pages"][0]["metadata"]["url"]
    assert result["pages"][0]["status"] == gotor["pages"][0]["metadata"]["status"]
    assert result["pages"][0]["links"] == [
        {"url": "https://example.com/child", "source": "anchor"}
    ]


def test_result_records_failures_and_filters_secret_diagnostics():
    tree = make_tree()
    tree.crawl_failures.append({
        "url": "https://example.com/unavailable", "parentUrl": "https://example.com/",
        "depth": 1, "outcome": "failed", "status": None, "skippedReason": None,
        "errorCategory": "network", "links": [], "contacts": [],
    })
    result = CrawlResultAdapter(tree, uses_tor=True).result(
        diagnostics={"proxy": "configured", "cookie": "do-not-store", "token": "do-not-store"}
    )

    assert result["terminalStatus"] == "completed"
    assert result["diagnostics"] == {"proxy": "configured"}
    assert result["pages"][-1]["errorCategory"] == "network"


def test_cancelled_and_invalid_input_fixtures_are_terminal_and_safe():
    cancelled = CrawlResultAdapter(make_tree(), uses_tor=False).result(
        terminal_status="cancelled"
    )
    invalid = invalid_result("not-a-url", run_id="invalid-run")

    assert cancelled["cancelled"] is True
    assert cancelled["terminalStatus"] == "cancelled"
    assert invalid["terminalStatus"] == "invalid"
    assert invalid["pages"] == [{
        "url": "not-a-url", "parentUrl": None, "depth": 0, "outcome": "failed",
        "status": None, "skippedReason": None, "errorCategory": "invalid_input",
        "links": [], "contacts": [],
    }]


def test_contract_fixtures_cover_terminal_and_page_outcomes():
    fixture_directory = Path(__file__).parent / "fixtures"
    fixtures = [
        json.loads(path.read_text())
        for path in fixture_directory.glob("torbot-v1-*.json")
    ]
    assert {fixture["terminalStatus"] for fixture in fixtures} == {
        "completed", "cancelled", "invalid"
    }
    outcomes = {page["outcome"] for fixture in fixtures for page in fixture["pages"]}
    assert {"fetched", "failed", "skipped"} <= outcomes
