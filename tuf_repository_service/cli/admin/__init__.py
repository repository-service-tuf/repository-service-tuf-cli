from tuf_repository_service.cli import trs


@trs.group()
def admin():
    """Administrative Commands"""
