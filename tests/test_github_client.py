"""Tests for GitHubClient with mocked PyGithub."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from pipeline.tools.github_client import GitHubClient


@pytest.fixture
def mock_gh():
    """Patch Github and return the mock instance."""
    with patch("pipeline.tools.github_client.Github") as MockGithub, \
         patch("pipeline.tools.github_client.Auth") as MockAuth:
        mock_instance = MagicMock()
        MockGithub.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def gh_client(mock_gh):
    """Create a GitHubClient with mocked PyGithub."""
    return GitHubClient(token="test-token")


class TestCreatePr:

    def test_returns_pr_url(self, gh_client, mock_gh):
        mock_repo = MagicMock()
        mock_pr = MagicMock()
        mock_pr.html_url = "https://github.com/vectimus/policies/pull/42"
        mock_repo.create_pull.return_value = mock_pr
        mock_gh.get_repo.return_value = mock_repo

        url = gh_client.create_pr(
            repo_name="vectimus/policies",
            title="Add prompt injection policy",
            body="New policy for VTMS-2026-0001",
            head="vtms-2026-0001/policy",
        )

        assert url == "https://github.com/vectimus/policies/pull/42"
        mock_repo.create_pull.assert_called_once_with(
            title="Add prompt injection policy",
            body="New policy for VTMS-2026-0001",
            head="vtms-2026-0001/policy",
            base="main",
        )

    def test_adds_labels_when_provided(self, gh_client, mock_gh):
        mock_repo = MagicMock()
        mock_pr = MagicMock()
        mock_pr.html_url = "https://github.com/vectimus/policies/pull/42"
        mock_repo.create_pull.return_value = mock_pr
        mock_gh.get_repo.return_value = mock_repo

        gh_client.create_pr(
            repo_name="vectimus/policies",
            title="Test PR",
            body="Body",
            head="feature-branch",
            labels=["sentinel", "auto-generated"],
        )

        mock_pr.add_to_labels.assert_called_once_with("sentinel", "auto-generated")

    def test_no_labels_added_when_none(self, gh_client, mock_gh):
        mock_repo = MagicMock()
        mock_pr = MagicMock()
        mock_pr.html_url = "https://github.com/test/pull/1"
        mock_repo.create_pull.return_value = mock_pr
        mock_gh.get_repo.return_value = mock_repo

        gh_client.create_pr(
            repo_name="test/repo",
            title="Test",
            body="Body",
            head="branch",
        )

        mock_pr.add_to_labels.assert_not_called()


class TestCreateBranch:

    def test_creates_git_ref(self, gh_client, mock_gh):
        mock_repo = MagicMock()
        mock_branch = MagicMock()
        mock_branch.commit.sha = "abc123"
        mock_repo.get_branch.return_value = mock_branch
        mock_gh.get_repo.return_value = mock_repo

        gh_client.create_branch("vectimus/policies", "vtms-2026-0001/policy")

        mock_repo.create_git_ref.assert_called_once_with(
            ref="refs/heads/vtms-2026-0001/policy",
            sha="abc123",
        )

    def test_uses_from_branch(self, gh_client, mock_gh):
        mock_repo = MagicMock()
        mock_branch = MagicMock()
        mock_branch.commit.sha = "def456"
        mock_repo.get_branch.return_value = mock_branch
        mock_gh.get_repo.return_value = mock_repo

        gh_client.create_branch("vectimus/policies", "new-branch", from_branch="develop")

        mock_repo.get_branch.assert_called_once_with("develop")


class TestPushFile:

    def test_creates_file_when_not_exists(self, gh_client, mock_gh):
        from github import GithubException

        mock_repo = MagicMock()
        mock_repo.get_contents.side_effect = GithubException(404, "Not Found", None)
        mock_gh.get_repo.return_value = mock_repo

        gh_client.push_file(
            repo_name="vectimus/policies",
            branch="vtms-2026-0001/policy",
            path="policies/prompt-injection.cedar",
            content="permit(...);",
            message="Add prompt injection policy",
        )

        mock_repo.create_file.assert_called_once_with(
            path="policies/prompt-injection.cedar",
            message="Add prompt injection policy",
            content="permit(...);",
            branch="vtms-2026-0001/policy",
        )

    def test_updates_file_when_exists(self, gh_client, mock_gh):
        mock_repo = MagicMock()
        mock_existing = MagicMock()
        mock_existing.sha = "existing-sha-123"
        mock_repo.get_contents.return_value = mock_existing
        mock_gh.get_repo.return_value = mock_repo

        gh_client.push_file(
            repo_name="vectimus/policies",
            branch="vtms-2026-0001/policy",
            path="policies/prompt-injection.cedar",
            content="forbid(...);",
            message="Update prompt injection policy",
        )

        mock_repo.update_file.assert_called_once_with(
            path="policies/prompt-injection.cedar",
            message="Update prompt injection policy",
            content="forbid(...);",
            sha="existing-sha-123",
            branch="vtms-2026-0001/policy",
        )


class TestGetPrByBranch:

    def test_returns_dict_when_pr_found(self, gh_client, mock_gh):
        mock_repo = MagicMock()
        mock_owner = MagicMock()
        mock_owner.login = "vectimus"
        mock_repo.owner = mock_owner

        mock_pr = MagicMock()
        mock_pr.html_url = "https://github.com/vectimus/policies/pull/42"
        mock_pr.title = "Add policy"
        mock_pr.body = "New policy PR"
        mock_pr.number = 42

        mock_repo.get_pulls.return_value = [mock_pr]
        mock_gh.get_repo.return_value = mock_repo

        result = gh_client.get_pr_by_branch("vectimus/policies", "vtms-2026-0001/policy")

        assert result == {
            "url": "https://github.com/vectimus/policies/pull/42",
            "title": "Add policy",
            "body": "New policy PR",
            "number": 42,
        }

    def test_returns_none_when_no_pr(self, gh_client, mock_gh):
        mock_repo = MagicMock()
        mock_owner = MagicMock()
        mock_owner.login = "vectimus"
        mock_repo.owner = mock_owner
        mock_repo.get_pulls.return_value = []
        mock_gh.get_repo.return_value = mock_repo

        result = gh_client.get_pr_by_branch("vectimus/policies", "nonexistent-branch")

        assert result is None
