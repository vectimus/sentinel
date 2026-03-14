"""GitHub API client for cross-repo PR creation."""

from __future__ import annotations

from github import Auth, Github, GithubException


class GitHubClient:
    """Client for GitHub operations across multiple repos."""

    def __init__(self, token: str) -> None:
        auth = Auth.Token(token)
        self._gh = Github(auth=auth)

    def create_pr(
        self,
        repo_name: str,
        title: str,
        body: str,
        head: str,
        base: str = "main",
        labels: list[str] | None = None,
        reviewers: list[str] | None = None,
    ) -> str:
        """Create a pull request and return the PR URL."""
        repo = self._gh.get_repo(repo_name)
        pr = repo.create_pull(title=title, body=body, head=head, base=base)

        if labels:
            pr.add_to_labels(*labels)

        if reviewers:
            try:
                pr.create_review_request(reviewers=reviewers)
            except GithubException:
                pass  # Reviewer may not have access

        return pr.html_url

    def create_branch(self, repo_name: str, branch_name: str, from_branch: str = "main") -> None:
        """Create a new branch from an existing branch."""
        repo = self._gh.get_repo(repo_name)
        source = repo.get_branch(from_branch)
        repo.create_git_ref(
            ref=f"refs/heads/{branch_name}",
            sha=source.commit.sha,
        )

    def push_file(
        self,
        repo_name: str,
        branch: str,
        path: str,
        content: str,
        message: str,
    ) -> None:
        """Create or update a file on a branch."""
        repo = self._gh.get_repo(repo_name)
        try:
            existing = repo.get_contents(path, ref=branch)
            repo.update_file(
                path=path,
                message=message,
                content=content,
                sha=existing.sha,
                branch=branch,
            )
        except GithubException:
            repo.create_file(
                path=path,
                message=message,
                content=content,
                branch=branch,
            )

    def get_pr_by_branch(self, repo_name: str, branch: str) -> dict | None:
        """Find a PR by head branch name."""
        repo = self._gh.get_repo(repo_name)
        prs = repo.get_pulls(state="open", head=f"{repo.owner.login}:{branch}")
        for pr in prs:
            return {
                "url": pr.html_url,
                "title": pr.title,
                "body": pr.body,
                "number": pr.number,
            }
        return None

    def close(self) -> None:
        self._gh.close()
