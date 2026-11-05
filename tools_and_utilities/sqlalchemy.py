import datetime
from typing import List
from sqlalchemy import create_engine
from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import object_session
from sqlalchemy.orm import relationship
from sqlalchemy.orm import Session
from sqlalchemy.ext.associationproxy import AssociationProxy
from sqlalchemy.ext.associationproxy import association_proxy


class Base(DeclarativeBase):
    pass

class MappedInit(object):
    def __init__(self, cmd):
        for c in self.__table__.columns:
            col = c.key
            val = cmd.__getattribute__(col)
            self.__setattr__(col, val)


class NavigationEntry(Base):
    __tablename__ = "navigation_entry"

    index: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str]
    title: Mapped[str]
    page_state_raw: Mapped[bytes]
    transition_type: Mapped[str]    # possible PickleType
    has_post_data: Mapped[bool]
    referrer_url: Mapped[str]
    original_request_url: Mapped[str]
    is_overriding_user_agent: Mapped[bool]
    timestamp: Mapped[datetime.datetime]
    http_status: Mapped[int]
    referrer_policy: Mapped[int]
    extended_map: Mapped[str]   # possible PickleType (dict)
    task_id: Mapped[int]
    parent_task_id: Mapped[int]
    root_task_id: Mapped[int]
    session_id: Mapped[int] = mapped_column(ForeignKey("tab_window.tab_id"), primary_key=True)

    def __init__(self, cmd):
        for c in self.__table__.columns:
            col = c.key
            if col == 'transition_type':
                val = cmd.transition_type.__str__()
            elif col == 'extended_map':
                val = cmd.extended_map.__str__()
            else:
                val = cmd.__getattribute__(col)
            self.__setattr__(col, val)


class NavigationIndex(MappedInit, Base):
    __tablename__ = "navigation_index"

    tab_id: Mapped[int] = mapped_column(ForeignKey("tab_window.tab_id"), primary_key=True)
    index: Mapped[int]


class TabIndexInWindow(MappedInit, Base):
    __tablename__ = "tab_index_in_window"

    tab_id: Mapped[int] = mapped_column(ForeignKey("tab_window.tab_id"), primary_key=True)
    index: Mapped[int]


class TabInIndex(MappedInit, Base):
    __tablename__ = "tab_in_index"

    win_id: Mapped[int] = mapped_column(ForeignKey("window.win_id"), primary_key=True)
    index: Mapped[int]


class TabWindow(MappedInit, Base):
    __tablename__ = "tab_window"

    win_id: Mapped[int] = mapped_column(ForeignKey("window.win_id"))
    tab_id: Mapped[int] = mapped_column(primary_key=True)

    _nav_entries: Mapped[List["NavigationEntry"]] = relationship()
    _navigation_index: Mapped["NavigationIndex"] = relationship()
    navigation_index: AssociationProxy[int] = association_proxy('_navigation_index', 'index')
    _tab_index: Mapped["TabIndexInWindow"] = relationship()
    tab_index: AssociationProxy[int] = association_proxy('_tab_index', 'index')

    @property
    def navigation(self):
        return object_session(self)\
                .query(NavigationEntry)\
                .filter(NavigationEntry.session_id == self.tab_id)\
                .filter(NavigationEntry.index == self.navigation_index)\
                .one()


class Window(Base):
    __tablename__ = "window"

    win_id: Mapped[int] = mapped_column(primary_key=True)

    tabs: Mapped[List["TabWindow"]] = relationship()
    _tab_in_index: Mapped["TabInIndex"] = relationship()
    tab_in_index: AssociationProxy[int] = association_proxy('_tab_in_index', 'index')


def db_from_cmd_list(cmd_list, db:Session):
    """
    function to populate database from session state commands
    
    db:         sqlaclchemy session
    cmd_list    list of session state commands
                sample code to build cmd_list:
                    with open(file_url,"rb") as snss_io:
                        snss_file = ccl_chromium_snss2.SnssFile(ccl_chromium_snss2.SnssFileType(1), snss_io)

                        cmd = []
                        for command in snss_file.iter_session_commands():
                            cmd.append(command)
    """
    for c in cmd_list:
        if type(c) is snss2.WindowType:
            db.merge(Window(win_id=c.win_id))

        elif type(c) is snss2.NavigationEntry:
            db.merge(NavigationEntry(c))

        elif type(c) is snss2.TabWindow:
            db.merge(TabWindow(c))

        elif type(c) is snss2.TabIndexInWindow:
            db.merge(TabIndexInWindow(c))

        elif type(c) is snss2.NavigationIndex:
            db.merge(NavigationIndex(c))

        elif type(c) is snss2.TabInIndex:
            db.merge(TabInIndex(c))
    
    db.commit()
