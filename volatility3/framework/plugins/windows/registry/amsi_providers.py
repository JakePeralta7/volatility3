# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterator, List, Tuple, Optional

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import registry
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


class AmsiProviders(interfaces.plugins.PluginInterface):
    """Lists AMSI (Antimalware Scan Interface) providers from the registry."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="hivelist", component=hivelist.HiveList, version=(2, 0, 0)
            ),
        ]

    @staticmethod
    def _get_default_value(key) -> Optional[str]:
        """Extract the default value from a registry key."""
        try:
            values_found = False
            for value in key.get_values():
                values_found = True
                value_name = value.get_name()
                vollog.debug(f"Found value: name='{value_name}', type={value.Type}")
                if value_name in ["", "(Default)", None]:
                    data = value.decode_data()
                    if data and isinstance(data, bytes):
                        decoded = data.decode("utf-16-le", errors="replace").rstrip("\x00").strip()
                        if decoded:
                            return decoded.strip('"')
            if not values_found:
                vollog.debug(f"No values found in key")
        except (exceptions.InvalidAddressException, registry.RegistryException) as e:
            vollog.debug(f"Exception reading key values: {e}")
        return None

    @classmethod
    def list_amsi_providers(
        cls,
        context: interfaces.context.ContextInterface,
        base_config_path: str,
        kernel_module_name: str,
    ) -> Iterator[Tuple[str, str, str, str]]:
        """
        Enumerates AMSI providers from the registry.

        Args:
            context: The context to retrieve required elements from
            base_config_path: The configuration path
            kernel_module_name: The name of the kernel module

        Yields:
            Tuple of (architecture, provider_guid, provider_name, dll_path)
        """
        
        # Registry paths for 64-bit and 32-bit AMSI providers
        registry_paths = [
            ("WOW6432Node\\Microsoft\\AMSI\\Providers", "Classes\\Wow6432Node\\CLSID", "32bit"),
            ("Microsoft\\AMSI\\Providers", "Classes\\CLSID", "64bit"),
        ]
        
        for hive in hivelist.HiveList.list_hives(
            context=context,
            base_config_path=base_config_path,
            kernel_module_name=kernel_module_name,
            filter_string="software",
        ):
            for providers_path, clsid_base_path, architecture in registry_paths:
                try:
                    providers_key = hive.get_key(providers_path)
                except (KeyError, exceptions.InvalidAddressException, registry.RegistryException):
                    continue

                for provider_subkey in providers_key.get_subkeys():
                    try:
                        provider_guid = provider_subkey.get_name()
                        if not provider_guid or not provider_guid.startswith("{"):
                            continue

                        vollog.debug(f"Processing provider GUID: {provider_guid} from path: {providers_path}")

                        provider_name = renderers.NotAvailableValue()
                        dll_path = renderers.NotAvailableValue()

                        # Get provider name from CLSID registration
                        try:
                            clsid_key = hive.get_key(f"{clsid_base_path}\\{provider_guid}")
                            vollog.debug(f"Found CLSID key: {clsid_base_path}\\{provider_guid}")
                            name = cls._get_default_value(clsid_key)
                            if name:
                                provider_name = name
                                vollog.debug(f"Found provider name: {name}")
                        except (KeyError, exceptions.InvalidAddressException, registry.RegistryException) as e:
                            vollog.debug(f"Could not find CLSID key {clsid_base_path}\\{provider_guid}: {e}")

                        # Get DLL path from InprocServer32
                        try:
                            inproc_key = hive.get_key(f"{clsid_base_path}\\{provider_guid}\\InprocServer32")
                            vollog.debug(f"Found InprocServer32 key: {clsid_base_path}\\{provider_guid}\\InprocServer32")
                            path = cls._get_default_value(inproc_key)
                            if path:
                                dll_path = path
                                vollog.debug(f"Found DLL path: {path}")
                        except (KeyError, exceptions.InvalidAddressException, registry.RegistryException) as e:
                            vollog.debug(f"Could not find InprocServer32 key: {e}")

                        yield (architecture, provider_guid, provider_name, dll_path)

                    except (exceptions.InvalidAddressException, registry.RegistryException):
                        continue

    def _generator(self) -> Iterator[Tuple[int, Tuple[str, str, str, str]]]:
        """Generator that yields AMSI provider information for rendering."""
        for architecture, provider_guid, provider_name, dll_path in self.list_amsi_providers(
            context=self.context,
            base_config_path=self.config_path,
            kernel_module_name=self.config["kernel"],
        ):
            yield (0, (architecture, provider_guid, provider_name, dll_path))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Architecture", str),
                ("Provider GUID", str),
                ("Provider Name", str),
                ("DLL Path", str),
            ],
            self._generator(),
        )
