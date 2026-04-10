from io import BytesIO
from typing import Optional

from requests import get
import os
from uuid import uuid4

from tools import config as c


class File(BytesIO):
    def __init__(self, url: str, file_name: Optional[str] = None):
        self._url = url
        if file_name:
            self.filename = file_name
        else:
            self.filename = url.split("/")[-1]
        super().__init__()

        r = get(self._url, allow_redirects=True)
        self.write(r.content)
        self.seek(0)


class FileOld:
    def __init__(self, url: str, file_name: Optional[str] = None):
        self.url = url
        if file_name:
            self.filename = file_name
        else:
            self.filename = url.split("/")[-1]
        self.path = ""

    def read(self):
        if not self.path:
            # self.path = os.path.join(c.TASKS_UPLOAD_FOLDER, str(uuid4()))
            self.path = os.path.join(c.TASKS_UPLOAD_FOLDER, self.filename)
            r = get(self.url, allow_redirects=True)
            with open(self.path, 'wb') as f:
                f.write(r.content)
                return r.content

    def seek(self, offset, whence=0):
        with open(self.path, 'rb') as f:
            return f.seek(offset, whence)

    def tell(self):
        with open(self.path, 'rb') as f:
            f.seek(0, 2)
            return f.tell()

    def remove(self):
        os.remove(self.path)
