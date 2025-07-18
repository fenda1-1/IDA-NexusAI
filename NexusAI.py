import sys
import os
import idaapi

plugin_dir = os.path.dirname(os.path.abspath(__file__))
if plugin_dir not in sys.path:
    sys.path.append(plugin_dir)

from NexusAI.Core.plugin import NexusAIPlugin

def PLUGIN_ENTRY():
    return NexusAIPlugin()
