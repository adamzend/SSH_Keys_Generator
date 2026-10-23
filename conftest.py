# SPDX-License-Identifier: GPL-3.0-only
# (C) Adam Wojcieszonek 2026
"""Run Tk GUI tests in separate processes, matching the desktop app lifecycle."""
import os
import subprocess
import sys
import pytest

@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    if os.environ.get('SSHKG_GUI_TEST_CHILD') == '1':return None
    if not (pyfuncitem.name.startswith('test_gui_') or pyfuncitem.name=='test_profile_switch_disconnects_and_busy_guard'):
        return None
    env=dict(os.environ,SSHKG_GUI_TEST_CHILD='1')
    result=subprocess.run([sys.executable,'-m','pytest',str(pyfuncitem.path)+'::'+pyfuncitem.name,'-q'],
                          env=env,capture_output=True,text=True,timeout=60)
    assert result.returncode==0,result.stdout+'\n'+result.stderr
    return True
