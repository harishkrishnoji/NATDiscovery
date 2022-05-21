import gitlab


class GitLab_Client:
    """Initial GitLab Client."""

    def __init__(self, filepath="", project_id="4504", branch="master", token="") -> None:
        self.url = "https://git-enterprise-jc.onefiserv.net"
        self.project_id = project_id
        self.branch = branch
        self.filepath = filepath
        self.gl = gitlab.Gitlab(url=self.url, private_token=token)
        self.proj_lst = self.gl.projects.list()
        self.proj = self.gl.projects.get(project_id)
        self.proj_tree = self.proj.repository_tree()

    def get_file(self):
        try:
            return self.proj.files.get(file_path=self.filepath, ref=self.branch)
        except gitlab.exceptions.GitlabGetError:
            pass

    def update_file(self, lfilepath):
        file = self.get_file()
        if file:
            with open(lfilepath, "r") as my_file:
                file_content = my_file.read()
            file.content = file_content
            resp = file.save(
                branch=self.branch,
                commit_message=f"Update {self.filepath}",
                author_email="harish.krishnoji@fiserv.com",
                author_name="Harish Krishnoji",
            )
            return resp
        else:
            self.create_file(lfilepath)

    def delete_file(self):
        return self.proj.delete(commit_message=f"Delete {self.filepath}", branch=self.branch)

    def create_file(self, lfilepath):
        with open(lfilepath, "r") as my_file:
            file_content = my_file.read()
        resp = self.proj.files.create(
            {
                "file_path": self.filepath,
                "branch": self.branch,
                "content": file_content,
                "author_email": "harish.krishnoji@fiserv.com",
                "author_name": "Harish Krishnoji",
                "commit_message": f"Create {self.filepath}",
            }
        )
        return resp
