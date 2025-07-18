import json
from pathlib import Path
from typing import Dict, List, Set, Tuple

import idaapi  # type: ignore
import idautils  # type: ignore
import idc  # type: ignore


# ---------------------------------------------------------------------------
# GraphExporter
# 图导出器
# ---------------------------------------------------------------------------
__nexus_extension__ = False  # 标记为非扩展

class GraphExporter:
    """
    导出调用图与数据流图到 JSON 文件，供 AI 模型消费。
    Export call graphs and data flow graphs to JSON files for AI model consumption.
    """

    def __init__(self, output_dir: Path | None = None):
        # 修改：默认输出目录为当前脚本所在目录下的 "data" 文件夹
        script_dir = Path(__file__).resolve().parent
        self.output_dir = output_dir or script_dir / "data"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self) -> Tuple[Path, Path]:
        """
        构建两类图并写入 JSON 文件，返回文件路径元组。
        Build two types of graphs and write them to JSON files, returning a tuple of file paths.
        """
        try:
            import ida_funcs  # type: ignore
            total_funcs = ida_funcs.get_func_qty()
        except Exception:
            import idautils  # type: ignore
            total_funcs = sum(1 for _ in idautils.Functions())

        idaapi.show_wait_box(f"NexusAI: 构建调用图 0/{total_funcs}")

        call_graph = self._build_call_graph(total_funcs)

        idaapi.replace_wait_box("NexusAI: 构建数据流图…")
        data_flow_graph = self._build_data_flow_graph(total_funcs)

        idaapi.hide_wait_box()

        call_graph_path = self.output_dir / "call_graph.json"
        data_flow_path = self.output_dir / "data_flow_graph.json"

        self._dump_json(call_graph_path, call_graph)
        self._dump_json(data_flow_path, data_flow_graph)

        return call_graph_path, data_flow_path

    def export_subgraph(self, root_ea: int, depth: int = 2) -> Tuple[Path, Path]:
        """
        仅导出以指定函数为根、限定深度的子调用/数据流图。
        Export only the sub-call/data flow graph with the specified function as the root and limited depth.
        """
        call_graph = self._build_call_subgraph(root_ea, depth)
        data_flow_graph = self._build_data_flow_subgraph(call_graph)

        call_graph_path = self.output_dir / f"call_graph_{root_ea:08X}.json"
        data_flow_path = self.output_dir / f"data_flow_graph_{root_ea:08X}.json"

        self._dump_json(call_graph_path, call_graph)
        self._dump_json(data_flow_path, data_flow_graph)

        for p in (call_graph_path, data_flow_path):
            if p.stat().st_size > 2 * 1024 * 1024:  # >2 MB
                self._compress_file(p)

        return call_graph_path, data_flow_path

    def _build_call_graph(self, total_funcs: int | None = None) -> Dict[str, List[dict]]:
        """
        遍历所有函数，提取调用关系。
        Traverse all functions and extract calling relationships.
        """
        nodes: List[dict] = []
        edges: Set[Tuple[int, int]] = set()

        processed = 0
        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:08X}"
            nodes.append({"id": func_ea, "name": func_name})

            for insn_ea in idautils.FuncItems(func_ea):
                if idaapi.is_call_insn(insn_ea):
                    callee = idc.get_operand_value(insn_ea, 0)
                    if callee and idaapi.get_func(callee):
                        edges.add((func_ea, callee))
            processed += 1
            if total_funcs and processed % 256 == 0:
                idaapi.replace_wait_box(f"NexusAI: 构建调用图 {processed}/{total_funcs} ({processed*100/total_funcs:.1f}% )")

        edge_dicts = [{"src": src, "dst": dst} for src, dst in edges]
        return {"nodes": nodes, "edges": edge_dicts}

    def _build_data_flow_graph(self, total_funcs: int | None = None) -> Dict[str, List[dict]]:
        """
        构建简化的数据流图：函数 ↔️ 全局变量/地址 访问。
        Build a simplified data flow graph: function ↔️ global variable/address access.
        """
        nodes: List[dict] = []
        edges: List[dict] = []
        data_nodes_seen: Set[int] = set()

        processed = 0
        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:08X}"
            nodes.append({"id": func_ea, "type": "function", "name": func_name})

            referenced_data: Set[int] = set()
            for insn_ea in idautils.FuncItems(func_ea):
                for data_ref in idautils.DataRefsFrom(insn_ea):
                    referenced_data.add(data_ref)

            for d_ea in referenced_data:
                if d_ea not in data_nodes_seen:
                    data_name = idc.get_name(d_ea, idaapi.GN_VISIBLE) or f"data_{d_ea:08X}"
                    nodes.append({"id": d_ea, "type": "data", "name": data_name})
                    data_nodes_seen.add(d_ea)
                edges.append({"src": func_ea, "dst": d_ea})
            processed += 1
            if total_funcs and processed % 256 == 0:
                idaapi.replace_wait_box(f"NexusAI: 构建数据流图 {processed}/{total_funcs} ({processed*100/total_funcs:.1f}% )")

        return {"nodes": nodes, "edges": edges}

    def _build_call_subgraph(self, root_ea: int, max_depth: int) -> Dict[str, List[dict]]:
        """
        基于 BFS 的限定深度子调用图。
        Limited depth subcall graph based on BFS.
        """
        visited: Set[int] = set()
        edges: Set[Tuple[int, int]] = set()
        queue: List[Tuple[int, int]] = [(root_ea, 0)]

        while queue:
            func_ea, depth = queue.pop(0)
            if func_ea in visited or depth > max_depth:
                continue
            visited.add(func_ea)

            for insn_ea in idautils.FuncItems(func_ea):
                if idaapi.is_call_insn(insn_ea):
                    callee = idc.get_operand_value(insn_ea, 0)
                    if callee and idaapi.get_func(callee):
                        edges.add((func_ea, callee))
                        queue.append((callee, depth + 1))

        nodes = [
            {"id": ea, "name": idc.get_func_name(ea) or f"sub_{ea:08X}"}
            for ea in visited
        ]
        edge_dicts = [{"src": s, "dst": d} for s, d in edges if s in visited and d in visited]
        return {"nodes": nodes, "edges": edge_dicts}

    def _build_data_flow_subgraph(self, call_graph: Dict[str, List[dict]]):
        """
        基于调用子图收集数据流信息。
        Collect data flow information based on the call subgraph.
        """
        func_eas = {n["id"] for n in call_graph["nodes"]}
        nodes: List[dict] = []
        edges: List[dict] = []
        data_nodes_seen: Set[int] = set()

        for func_ea in func_eas:
            func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:08X}"
            nodes.append({"id": func_ea, "type": "function", "name": func_name})

            referenced_data: Set[int] = set()
            for insn_ea in idautils.FuncItems(func_ea):
                for data_ref in idautils.DataRefsFrom(insn_ea):
                    referenced_data.add(data_ref)

            for d_ea in referenced_data:
                if d_ea not in data_nodes_seen:
                    data_name = idc.get_name(d_ea, idaapi.GN_VISIBLE) or f"data_{d_ea:08X}"
                    nodes.append({"id": d_ea, "type": "data", "name": data_name})
                    data_nodes_seen.add(d_ea)
                edges.append({"src": func_ea, "dst": d_ea})

        return {"nodes": nodes, "edges": edges}

    @staticmethod
    def _dump_json(path: Path, data):
        with path.open("w", encoding="utf-8") as fp:
            json.dump(data, fp, ensure_ascii=False, indent=2)

    @staticmethod
    def _compress_file(path: Path):
        import gzip, shutil

        gz_path = path.with_suffix(path.suffix + ".gz")
        with path.open("rb") as src, gzip.open(gz_path, "wb") as dst:
            shutil.copyfileobj(src, dst)
        path.unlink()
        return gz_path