import ZeekControl.plugin
import os


class XDPZeek(ZeekControl.plugin.Plugin):
    def __init__(self):
        super().__init__(apiversion=1)

    def name(self):
        return "xdp"

    def pluginVersion(self):
        return 1

    def options(self):
        plugin_dir = os.path.dirname(os.path.abspath(__file__))
        default_path = os.path.join(plugin_dir, "..", "bpf", "filter.o")
        default_path = os.path.normpath(default_path)

        return [
            ("enabled", "bool", False, "Set to enable plugin"),
            ("Program", "string", default_path, "The XDP program"),
            ("PinPath", "string", "/sys/fs/bpf/zeek/", "The XDP pin path"),
        ]

    def init(self):
        xdp_program = self.getOption("Program")
        xdp_pin_path = self.getOption("PinPath")
        if not xdp_program:
            return False

        if not xdp_pin_path:
            # TODO: error here?
            return False

        return True

    def uniq_nodes(self, nodes):
        return {
            (node.host, node.interface): node for node in nodes if node.interface
        }.values()

    # Gets the interface without potential prefixes
    def get_interface(self, node):
        return node.interface.rpartition("::")[-1]

    def cmd_start_pre(self, nodes):
        # Load the XDP program on each unique interface
        cmds = {
            (
                node,
                " ".join(
                    [
                        "xdp-loader",
                        "load",
                        self.get_interface(node),
                        self.getOption("Program"),
                        "-p",
                        self.getOption("PinPath"),
                    ]
                ),
            )
            for node in self.uniq_nodes(nodes)
        }

        for node, success, output in self.executeParallel(cmds):
            if success:
                self.debug(f"Loaded XDP program on {self.get_interface(node)}")
            else:
                # This is an issue
                self.error(
                    f"Failed to load XDP program on {self.get_interface(node)}: {output}"
                )

        return nodes

    def cmd_stop_post(self, nodes):
        # stop has different nodes
        nodes = [node[0] for node in nodes]

        # Unload the XDP program from each unique interface
        cmds = {
            (
                node,
                " ".join(
                    [
                        "xdp-loader",
                        "unload",
                        self.get_interface(node),
                        "--all",  # TODO: Don't unload all!
                    ]
                ),
            )
            for node in self.uniq_nodes(nodes)
        }

        for node, success, output in self.executeParallel(cmds):
            if success:
                self.debug(f"Unloaded XDP program on {self.get_interface(node)}")
            else:
                # Debug since this may not be an issue
                self.debug(
                    f"Failed to unload XDP program on {self.get_interface(node)}: {output}"
                )

        return nodes
