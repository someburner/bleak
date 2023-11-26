"""
Agent
-----

This module contains types associated with the BlueZ D-Bus `agent api
<https://github.com/bluez/bluez/blob/master/doc/agent-api.txt>`.
"""

import asyncio
import contextlib
import logging
import os
from typing import Set, no_type_check

from dbus_fast import DBusError, Message
from dbus_fast.aio import MessageBus
from dbus_fast.service import ServiceInterface, method

from bleak.backends.device import BLEDevice

from ...agent import BaseBleakAgentCallbacks
from . import defs
from .manager import get_global_bluez_manager
from .utils import assert_reply

logger = logging.getLogger(__name__)


class Agent(ServiceInterface):
    """
    Implementation of the org.bluez.Agent1 D-Bus interface.
    """

    def __init__(self, callbacks: BaseBleakAgentCallbacks):
        """
        Args:
        """
        super().__init__(defs.AGENT_INTERFACE)
        self._callbacks = callbacks
        self._tasks: Set[asyncio.Task] = set()

    @method()
    def Release(self):
        logger.debug("Release")

    # REVISIT: mypy is broke, so we have to add redundant @no_type_check
    # https://github.com/python/mypy/issues/6583

    @method()
    @no_type_check
    async def RequestPinCode(self, device: "o") -> "s":  # noqa: F821
        logger.debug("RequestPinCode %s", device)
        raise NotImplementedError

    @method()
    @no_type_check
    async def DisplayPinCode(self, device: "o", pincode: "s"):  # noqa: F821
        logger.debug("DisplayPinCode %s %s", device, pincode)
        raise NotImplementedError

    @method()
    @no_type_check
    async def RequestPasskey(self, device: "o") -> "u":  # noqa: F821
        logger.debug("RequestPasskey %s", device)

        task = asyncio.create_task(self._callbacks.request_pin())
        self._tasks.add(task)

        try:
            pin = await task
        except asyncio.CancelledError:
            raise DBusError("org.bluez.Error.Canceled", "task canceled")
        finally:
            self._tasks.remove(task)

        if not pin:
            raise DBusError("org.bluez.Error.Rejected", "user rejected")

        return int(pin)

    @method()
    @no_type_check
    async def DisplayPasskey(
        self, device: "o", passkey: "u", entered: "q"  # noqa: F821
    ):
        passkey = f"{passkey:06}"
        logger.debug("DisplayPasskey %s %s %d", device, passkey, entered)
        raise NotImplementedError

    @method()
    @no_type_check
    async def RequestConfirmation(self, device: "o", passkey: "u"):  # noqa: F821
        passkey = f"{passkey:06}"
        logger.debug("RequestConfirmation %s %s", device, passkey)
        raise NotImplementedError

    @method()
    @no_type_check
    async def RequestAuthorization(self, device: "o"):  # noqa: F821
        logger.debug("RequestAuthorization %s", device)
        raise NotImplementedError

    @method()
    @no_type_check
    async def AuthorizeService(self, device: "o", uuid: "s"):  # noqa: F821
        logger.debug("AuthorizeService %s", device, uuid)
        raise NotImplementedError

    @method()
    @no_type_check
    def Cancel(self):  # noqa: F821
        logger.debug("Cancel")
        for t in self._tasks:
            t.cancel()


@contextlib.asynccontextmanager
async def bluez_agent(bus: MessageBus, callbacks: BaseBleakAgentCallbacks):
    agent = Agent(callbacks)

    # REVISIT: implement passing capability if needed
    # "DisplayOnly", "DisplayYesNo", "KeyboardOnly", "NoInputNoOutput", "KeyboardDisplay"
    capability = ""

    # this should be a unique path to allow multiple python interpreters
    # running bleak and multiple agents at the same time
    agent_path = f"/org/bleak/agent/{os.getpid()}/{id(agent)}"

    bus.export(agent_path, agent)

    try:
        reply = await bus.call(
            Message(
                destination=defs.BLUEZ_SERVICE,
                path="/org/bluez",
                interface=defs.AGENT_MANAGER_INTERFACE,
                member="RegisterAgent",
                signature="os",
                body=[agent_path, capability],
            )
        )

        assert_reply(reply)

        try:
            yield
        finally:
            reply = await bus.call(
                Message(
                    destination=defs.BLUEZ_SERVICE,
                    path="/org/bluez",
                    interface=defs.AGENT_MANAGER_INTERFACE,
                    member="UnregisterAgent",
                    signature="o",
                    body=[agent_path],
                )
            )

            assert_reply(reply)

    finally:
        bus.unexport(agent_path, agent)


class PinProviderAgentCallbacks(BaseBleakAgentCallbacks):
    def __init__(self, pin: str) -> None:
        super().__init__()
        self.pin = pin

    async def confirm(self, device: BLEDevice) -> bool:
        return True

    async def confirm_pin(self, device: BLEDevice, pin: str) -> bool:
        return True

    async def display_pin(self, device: BLEDevice, pin: str) -> None:
        # raise NotImplementedError
        print(f"{device.name} wants to pair.")
        print(f"enter this pin on the device: {pin}")
        # wait for cancellation
        await asyncio.Event().wait()

    async def request_pin(self) -> str:
        print(f"device wants to pair. Using pin: {self.pin}")
        return self.pin
