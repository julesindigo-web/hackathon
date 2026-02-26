"""
SecurAI Guardian - GitLab API Client
Wrapper for GitLab REST API with error handling and rate limiting
"""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime
import gitlab
from gitlab.exceptions import GitlabError, GitlabHttpError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from .config import get_settings
from .models import Vulnerability, MergeRequest, Severity, VulnerabilitySource

logger = logging.getLogger(__name__)
settings = get_settings()


class GitLabClient:
    """GitLab API client with retry logic and error handling"""

    def __init__(self, token: str, url: str = "https://gitlab.com"):
        """
        Initialize GitLab client

        Args:
            token: GitLab personal access token or CI_JOB_TOKEN
            url: GitLab instance URL
        """
        self.client = gitlab.Gitlab(url, private_token=token)
        # Skip authentication verification for hackathon demo with dummy tokens
        if not token.startswith("glpat-dummytoken"):
            try:
                self.client.auth()  # Verify authentication
            except Exception as e:
                logger.warning(f"GitLab authentication failed: {e}. Will continue in degraded mode.")
        logger.info(f"GitLab client initialized for {url}")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(GitlabError)
    )
    def get_project(self, project_id: int):
        """Get project by ID with retry logic"""
        try:
            return self.client.projects.get(project_id)
        except GitlabHttpError as e:
            if e.response_code == 404:
                logger.error(f"Project {project_id} not found")
                raise
            elif e.response_code == 403:
                logger.error(f"Permission denied for project {project_id}")
                raise
            else:
                logger.warning(f"GitLab API error: {e}, retrying...")
                raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(GitlabError)
    )
    def get_merge_request(self, project_id: int, mr_iid: int):
        """Get merge request by IID with retry logic"""
        project = self.get_project(project_id)
        return project.mergerequests.get(mr_iid)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(GitlabError)
    )
    def create_merge_request(
        self,
        project_id: int,
        source_branch: str,
        target_branch: str,
        title: str,
        description: str,
        labels: Optional[List[str]] = None,
        remove_source_branch: bool = True
    ) -> MergeRequest:
        """
        Create a new merge request

        Args:
            project_id: GitLab project ID
            source_branch: Source branch name
            target_branch: Target branch name (usually main/master)
            title: MR title
            description: MR description
            labels: Optional list of labels
            remove_source_branch: Auto-remove source branch after merge

        Returns:
            Created merge request
        """
        project = self.get_project(project_id)

        mr = project.mergerequests.create({
            'source_branch': source_branch,
            'target_branch': target_branch,
            'title': title,
            'description': description,
            'labels': labels or [],
            'remove_source_branch': remove_source_branch
        })

        logger.info(f"Created MR !{mr.iid}: {title}")
        return MergeRequest(
            iid=mr.iid,
            project_id=project_id,
            title=title,
            description=description,
            source_branch=source_branch,
            target_branch=target_branch,
            url=mr.web_url,
            labels=labels or [],
            created_at=datetime.utcnow()
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(GitlabError)
    )
    def add_merge_request_note(
        self,
        project_id: int,
        mr_iid: int,
        body: str
    ) -> Dict[str, Any]:
        """
        Add a comment/note to a merge request

        Args:
            project_id: GitLab project ID
            mr_iid: Merge request IID
            body: Comment body (supports markdown)

        Returns:
            Created note
        """
        mr = self.get_merge_request(project_id, mr_iid)
        note = mr.notes.create({'body': body})
        logger.debug(f"Added note to MR !{mr_iid}")
        return {'id': note.id, 'body': note.body}

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(GitlabError)
    )
    def get_security_vulnerabilities(
        self,
        project_id: int,
        mr_iid: Optional[int] = None
    ) -> List[Vulnerability]:
        """
        Get security vulnerabilities from GitLab Security Dashboard

        Args:
            project_id: GitLab project ID
            mr_iid: Optional merge request IID to filter

        Returns:
            List of vulnerabilities
        """
        project = self.get_project(project_id)

        # Get security vulnerabilities
        vulns = project.security_vulnerabilities.list(all=True)

        result = []
        for vuln in vulns:
            # Filter by MR if specified
            if mr_iid and vuln.merge_request_iid != mr_iid:
                continue

            # Map to our Vulnerability model
            result.append(Vulnerability(
                id=str(vuln.id),
                source=VulnerabilitySource.SAST if vuln.scanner_type == 'sast' else VulnerabilitySource.DEPENDENCY,
                severity=Severity(vuln.severity.lower()),
                cvss_score=vuln.cvss_score,
                cve_id=vuln.cve_id,
                project_id=project_id,
                mr_iid=vuln.merge_request_iid,
                file_path=vuln.file_path,
                line_start=vuln.line_start or 1,
                line_end=vuln.line_end or 1,
                code_snippet=vuln.code_snippet or "",
                dependency_name=vuln.dependency_name,
                dependency_version=vuln.dependency_version,
                fixed_version=vuln.fixed_version,
                scanner_uuid=vuln.scanner_uuid,
                detected_at=vuln.detected_at or datetime.utcnow()
            ))

        logger.info(f"Retrieved {len(result)} vulnerabilities for project {project_id}")
        return result

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(GitlabError)
    )
    def get_ci_artifacts(
        self,
        project_id: int,
        pipeline_id: int,
        job_name: str
    ) -> Optional[bytes]:
        """
        Download CI/CD job artifact

        Args:
            project_id: GitLab project ID
            pipeline_id: Pipeline ID
            job_name: Name of the job (e.g., 'sast', 'dependency-scanning')

        Returns:
            Artifact bytes or None if not found
        """
        project = self.get_project(project_id)

        try:
            pipeline = project.pipelines.get(pipeline_id)
            jobs = pipeline.jobs.list(all=True)

            # Find job by name
            job = next((j for j in jobs if j.name == job_name), None)
            if not job:
                logger.warning(f"Job '{job_name}' not found in pipeline {pipeline_id}")
                return None

            # Download artifact
            artifact = job.artifacts()
            if artifact:
                logger.info(f"Downloaded artifact from job '{job_name}' ({len(artifact)} bytes)")
                return artifact
            else:
                logger.warning(f"No artifact for job '{job_name}' in pipeline {pipeline_id}")
                return None

        except GitlabError as e:
            logger.error(f"Error fetching artifact: {e}")
            return None

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(GitlabError)
    )
    def trigger_pipeline(
        self,
        project_id: int,
        branch: str,
        variables: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Trigger a new CI/CD pipeline

        Args:
            project_id: GitLab project ID
            branch: Branch to run pipeline on
            variables: Optional pipeline variables

        Returns:
            Pipeline info dict
        """
        project = self.get_project(project_id)

        pipeline = project.pipelines.create({
            'ref': branch,
            'variables': variables or {}
        })

        logger.info(f"Triggered pipeline {pipeline.id} on {branch}")
        return {
            'id': pipeline.id,
            'status': pipeline.status,
            'web_url': pipeline.web_url
        }

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(GitlabError)
    )
    def update_vulnerability_status(
        self,
        project_id: int,
        vulnerability_id: str,
        status: str,
        resolution: Optional[str] = None
    ) -> bool:
        """
        Update vulnerability status (e.g., resolved, fixed)

        Args:
            project_id: GitLab project ID
            vulnerability_id: Vulnerability ID
            status: New status (resolved, fixed, etc.)
            resolution: Optional resolution explanation

        Returns:
            True if successful
        """
        project = self.get_project(project_id)

        try:
            vuln = project.security_vulnerabilities.get(vulnerability_id)
            vuln.state = status
            if resolution:
                vuln.resolution = resolution
            vuln.save()
            logger.info(f"Updated vulnerability {vulnerability_id} status to {status}")
            return True
        except GitlabError as e:
            logger.error(f"Failed to update vulnerability {vulnerability_id}: {e}")
            return False

    def get_repository_file(
        self,
        project_id: int,
        file_path: str,
        ref: str = "main"
    ) -> Optional[str]:
        """
        Get file content from repository

        Args:
            project_id: GitLab project ID
            file_path: Path to file in repository
            ref: Branch/tag/commit (default: main)

        Returns:
            File content as string or None if not found
        """
        try:
            project = self.get_project(project_id)
            file_item = project.files.get(file_path=file_path, ref=ref)
            return file_item.decode().decode('utf-8')
        except GitlabHttpError as e:
            if e.response_code == 404:
                logger.warning(f"File {file_path} not found in project {project_id}")
                return None
            else:
                logger.error(f"Error fetching file {file_path}: {e}")
                raise

    def create_repository_file(
        self,
        project_id: int,
        file_path: str,
        content: str,
        branch: str,
        commit_message: str
    ) -> bool:
        """
        Create or update file in repository

        Args:
            project_id: GitLab project ID
            file_path: Path to file
            content: File content
            branch: Branch to commit to
            commit_message: Commit message

        Returns:
            True if successful
        """
        try:
            project = self.get_project(project_id)

            # Check if file exists
            try:
                file_item = project.files.get(file_path=file_path, ref=branch)
                # Update existing file
                file_item.content = content
                file_item.save(branch=branch, commit_message=commit_message)
                logger.info(f"Updated file {file_path} in project {project_id}")
            except GitlabHttpError as e:
                if e.response_code == 404:
                    # Create new file
                    project.files.create({
                        'file_path': file_path,
                        'content': content,
                        'branch': branch,
                        'commit_message': commit_message
                    })
                    logger.info(f"Created file {file_path} in project {project_id}")
                else:
                    raise

            return True

        except GitlabError as e:
            logger.error(f"Failed to create/update file {file_path}: {e}")
            return False

    def get_commit_history(
        self,
        project_id: int,
        branch: str = "main",
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get commit history for a branch

        Args:
            project_id: GitLab project ID
            branch: Branch name
            limit: Maximum number of commits to return

        Returns:
            List of commit dicts
        """
        project = self.get_project(project_id)
        commits = project.commits.list(
            ref_name=branch,
            per_page=limit,
            all=False
        )

        result = []
        for commit in commits:
            result.append({
                'id': commit.id,
                'short_id': commit.short_id,
                'author_name': commit.author_name,
                'author_email': commit.author_email,
                'message': commit.message,
                'created_at': commit.created_at,
                'web_url': commit.web_url
            })

        return result


def get_gitlab_client() -> GitLabClient:
    """Factory function to create GitLab client from settings"""
    return GitLabClient(
        token=settings.gitlab_token,
        url=settings.gitlab_url
    )
