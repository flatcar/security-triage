from security_triage.reporting import render_discovery_markdown, summarize_discovery


def test_recommendations_are_not_counted_from_manual_action_alternatives():
    document = {
        "records": [
            {
                "source": "gentoo",
                "decision": {"action": "needs_manual_review"},
                "proposed_issue": {"title": "update: example"},
                "next_steps": ["Confirm whether the server component is shipped."],
            },
            {
                "source": "rustsec",
                "decision": {"action": "ignore"},
                "review_suppression": {"reason": "wrong_package", "suppressed": True},
            },
        ],
        "errors": [{"source": "oss-security", "error": "unavailable"}],
    }
    summary = summarize_discovery(document)
    assert summary == {
        "records": 2,
        "sources": {"gentoo": 1, "rustsec": 1},
        "recommendations": {"ignore": 1, "needs_manual_review": 1},
        "confirmed_feedback_suppressions": 1,
        "errors": 1,
    }
    rendered = render_discovery_markdown(document)
    assert "false-positive rate" in rendered
    assert "Confirm whether the server component is shipped." in rendered
    assert "wrong_package" in rendered
    assert "| create_issue |" not in rendered


def test_empty_discovery_summary_is_explicit():
    assert summarize_discovery({})["records"] == 0
    assert "No source entries were processed." in render_discovery_markdown({})


def test_tracking_feedback_does_not_count_as_suppression():
    assert (
        summarize_discovery(
            {"records": [{"review_suppression": {"suppressed": False}}]}
        )["confirmed_feedback_suppressions"]
        == 0
    )


def test_incomplete_feedback_coverage_is_visible():
    rendered = render_discovery_markdown(
        {
            "feedback_coverage": {
                "complete": False,
                "warnings": ["Suppression disabled."],
            }
        }
    )
    assert "Feedback history complete: False" in rendered
    assert "Suppression disabled." in rendered
