# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Plugin to detect potential AMSI bypass by identifying processes with AMSI loaded but missing provider DLLs."""

import logging
from typing import List, Set, Dict, Generator, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, dlllist, envars
from volatility3.plugins.windows.registry import amsi_providers

vollog = logging.getLogger(__name__)


class AmsiBypass(interfaces.plugins.PluginInterface):
    """Detects processes with AMSI loaded but missing expected AMSI provider DLLs."""

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
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),            requirements.VersionRequirement(
                name="dlllist", component=dlllist.DllList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="amsi_providers",
                component=amsi_providers.AmsiProviders,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="envars", component=envars.Envars, version=(1, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    @classmethod
    def get_amsi_provider_dlls(
        cls,
        context: interfaces.context.ContextInterface,
        base_config_path: str,
        kernel_module_name: str,
    ) -> Set[str]:
        """
        Retrieves the set of AMSI provider DLL paths from the registry.

        Returns:
            A set of lowercase DLL full paths
        """
        provider_dlls = set()

        for _, _, dll_path in amsi_providers.AmsiProviders.list_amsi_providers(
            context=context,
            base_config_path=base_config_path,
            kernel_module_name=kernel_module_name,
        ):
            if isinstance(dll_path, str) and dll_path:
                # Store the full lowercase path
                provider_dlls.add(dll_path.lower())

        return provider_dlls
    
    @classmethod
    def get_process_dlls(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        proc: interfaces.objects.ObjectInterface,
    ) -> Dict[str, int]:
        """
        Gets all DLLs loaded in a process using dlllist functionality.

        Returns:
            Dictionary mapping lowercase DLL full paths to their base addresses
        """
        loaded_dlls = {}

        try:
            # Use dlllist's method to enumerate DLLs
            for entry in proc.load_order_modules():
                try:
                    dll_path = entry.FullDllName.get_string()
                    if dll_path:
                        loaded_dlls[dll_path.lower()] = entry.DllBase
                except Exception:
                    continue
        except Exception as e:
            vollog.debug(
                f"Error enumerating DLLs for PID {proc.UniqueProcessId}: {e}"
            )
        return loaded_dlls

    @classmethod
    def expand_env_vars(
        cls,
        path: str,
        proc: interfaces.objects.ObjectInterface,
    ) -> str:
        """
        Expands environment variables in a path using process environment variables.

        Args:
            path: Path potentially containing environment variables (e.g., %ProgramData%)
            proc: Process object to extract environment variables from

        Returns:
            Path with environment variables expanded (lowercase)
        """
        if not path or '%' not in path:
            return path.lower()

        # Extract environment variables from the process
        env_vars = {}
        try:
            for var, val in proc.environment_variables():
                env_vars[var.upper()] = val
        except Exception as e:
            vollog.debug(f"Error reading environment variables for PID {proc.UniqueProcessId}: {e}")
            return path.lower()

        # Expand environment variables in the path
        expanded_path = path
        import re
        # Find all %VARNAME% patterns
        for match in re.finditer(r'%([^%]+)%', path, re.IGNORECASE):
            var_name = match.group(1).upper()
            if var_name in env_vars:
                expanded_path = expanded_path.replace(match.group(0), env_vars[var_name])

        return expanded_path.lower()

    def _generator(
        self,
    ) -> Generator[
        Tuple[int, Tuple[int, str, str, str, format_hints.Hex]], None, None
    ]:
        """
        Generates results for processes with AMSI loaded but missing provider DLLs.

        Yields:
            Tuples containing (tree_depth, (PID, Process Name, Status, Missing DLLs, AMSI Base Address))
        """
        kernel = self.context.modules[self.config["kernel"]]

        # Get expected AMSI provider DLLs from registry
        provider_dlls = self.get_amsi_provider_dlls(
            self.context, self.config_path, self.config["kernel"]
        )

        if not provider_dlls:
            vollog.warning(
                "No AMSI providers found in registry. This may indicate the system doesn't have AMSI configured."
            )

        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        for proc in pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=filter_func,
        ):
            try:
                process_name = utility.array_to_string(proc.ImageFileName)
                pid = proc.UniqueProcessId

                # Get all DLLs loaded in this process
                loaded_dlls = self.get_process_dlls(self.context, self.config["kernel"], proc)

                # Check if amsi.dll is loaded
                amsi_base = None
                has_amsi = False
                for dll_path, base_addr in loaded_dlls.items():
                    if dll_path.endswith("\\amsi.dll"):
                        has_amsi = True
                        amsi_base = base_addr
                        break

                # If AMSI is loaded, check for provider DLLs
                if has_amsi:
                    missing_providers = []
                    found_providers = []

                    for provider_dll in provider_dlls:
                        # Expand environment variables in the expected provider path using process env vars
                        expanded_provider_dll = self.expand_env_vars(provider_dll, proc)
                        
                        if expanded_provider_dll in loaded_dlls:
                            found_providers.append(provider_dll)
                        else:
                            missing_providers.append(provider_dll)

                    # Report if any expected providers are missing
                    if missing_providers:
                        status = "SUSPICIOUS - AMSI Loaded, Providers Missing"
                        missing_dlls_str = ", ".join(missing_providers)
                        yield (
                            0,
                            (
                                pid,
                                process_name,
                                status,
                                missing_dlls_str,
                                format_hints.Hex(amsi_base) if amsi_base else format_hints.Hex(0),
                            ),
                        )
                    else:
                        # Optionally report processes with AMSI and all providers loaded (normal case)
                        # Uncomment the following lines if you want to see all AMSI-using processes
                        # status = "Normal - AMSI with all providers"
                        # yield (0, (pid, process_name, status, "All present", format_hints.Hex(amsi_base)))
                        pass

            except Exception as e:
                vollog.debug(f"Error processing PID {proc.UniqueProcessId}: {e}")
                continue

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Status", str),
                ("Missing Provider DLLs", str),
                ("AMSI Base Address", format_hints.Hex),
            ],
            self._generator(),
        )
