# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterator, List, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import registry
from volatility3.framework.symbols.windows.extensions import registry as reg_extensions
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

    @classmethod
    def list_amsi_providers(
        cls,
        context: interfaces.context.ContextInterface,
        base_config_path: str,
        kernel_module_name: str,
    ) -> Iterator[Tuple[str, str, str]]:
        """
        Enumerates AMSI providers from the registry.

        Args:
            context: The context to retrieve required elements from
            base_config_path: The configuration path
            kernel_module_name: The name of the kernel module

        Yields:
            Tuple of (provider_guid, provider_name, dll_path)
        """
        
        # AMSI providers are registered in SOFTWARE hive
        for hive in hivelist.HiveList.list_hives(
            context=context,
            base_config_path=base_config_path,
            kernel_module_name=kernel_module_name,
            filter_string="software",
        ):
            try:
                # Try to get the AMSI Providers key
                providers_key = hive.get_key("Microsoft\\AMSI\\Providers")
            except (KeyError, exceptions.InvalidAddressException, registry.RegistryException):
                continue

            if not providers_key:
                continue            # Iterate through each provider GUID subkey
            for provider_subkey in providers_key.get_subkeys():
                provider_guid = renderers.NotAvailableValue()
                provider_name = renderers.NotAvailableValue()
                dll_path = renderers.NotAvailableValue()

                try:
                    # Get the GUID (subkey name)
                    provider_guid = provider_subkey.get_name()
                except (exceptions.InvalidAddressException, registry.RegistryException):
                    vollog.debug("Failed to get provider GUID")
                    continue

                # Skip if we don't have a valid GUID
                if not isinstance(provider_guid, str):
                    continue                # AMSI providers are COM objects, look up their CLSID registration
                if provider_guid.startswith("{"):
                    try:
                        # Get the provider name from CLSID root key
                        clsid_key_path = f"Classes\\CLSID\\{provider_guid}"
                        clsid_key = hive.get_key(clsid_key_path)
                        
                        # Get the default value which contains the provider name
                        for value in clsid_key.get_values():
                            value_name = value.get_name()
                            if value_name in ["", "(Default)", None]:
                                try:
                                    data = value.decode_data()
                                    if data and isinstance(data, bytes):
                                        decoded = data.decode("utf-16-le", errors="replace").rstrip("\x00")
                                        if decoded.strip():
                                            provider_name = decoded
                                            break
                                except (exceptions.InvalidAddressException, registry.RegistryException):
                                    pass
                    except (KeyError, exceptions.InvalidAddressException, registry.RegistryException):
                        vollog.debug(f"Could not find CLSID registration for {provider_guid}")

                    # Get the DLL path from InprocServer32
                    try:
                        clsid_key_path = f"Classes\\CLSID\\{provider_guid}\\InprocServer32"
                        inproc_key = hive.get_key(clsid_key_path)
                        
                        # Get the default value which contains the DLL path
                        for value in inproc_key.get_values():
                            value_name = value.get_name()
                            if value_name in ["", "(Default)", None]:
                                try:
                                    data = value.decode_data()
                                    if data and isinstance(data, bytes):
                                        decoded = data.decode("utf-16-le", errors="replace").rstrip("\x00")
                                        if decoded.strip():
                                            dll_path = decoded
                                            break
                                except (exceptions.InvalidAddressException, registry.RegistryException):
                                    pass
                    except (KeyError, exceptions.InvalidAddressException, registry.RegistryException):
                        vollog.debug(f"Could not find InprocServer32 for {provider_guid}")

                # Yield the provider information
                yield (provider_guid, provider_name, dll_path)

    def _generator(self) -> Iterator[Tuple[int, Tuple[str, str, str]]]:
        """
        Generator that yields AMSI provider information for rendering.

        Yields:
            Tuple of (tree_depth, (provider_guid, provider_name, dll_path))
        """
        for provider_guid, provider_name, dll_path in self.list_amsi_providers(
            context=self.context,
            base_config_path=self.config_path,
            kernel_module_name=self.config["kernel"],
        ):
            yield (0, (provider_guid, provider_name, dll_path))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Provider GUID", str),
                ("Provider Name", str),
                ("DLL Path", str),
            ],
            self._generator(),
        )
