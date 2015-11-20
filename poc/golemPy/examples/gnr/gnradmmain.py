import logging
import logging.config
import os
import sys

sys.path.append(os.environ.get('GOLEM'))

from tools.uigen import gen_ui_files

gen_ui_files("ui")

from examples.gnr.gnradmapplicationlogic import GNRAdmApplicationLogic
from examples.gnr.application import GNRGui
from examples.gnr.ui.mainwindow import GNRMainWindow
from examples.gnr.customizers.gnradministratormainwindowcustomizer import GNRAdministratorMainWindowCustomizer
from gnrstartapp import start_app


def main():
    logging.config.fileConfig('logging.ini', disable_existing_loggers=False)

    logic = GNRAdmApplicationLogic()
    app = GNRGui(logic, GNRMainWindow)
    gui = GNRAdministratorMainWindowCustomizer
    start_app(logic, app, gui, start_manager=True, start_info_server=True)


from multiprocessing import freeze_support

if __name__ == "__main__":
    freeze_support()
    main()
