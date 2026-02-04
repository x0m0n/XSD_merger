import xml.etree.cElementTree as ET
import os
from dataclasses import dataclass, field

class ElementNode:
    def __init__(self, tag, attrib, text, path,name=None):
        self.tag = tag
        self.attrib = dict(attrib)
        self.name = name
        self.text = (text or "").strip()
        self.path = path          # absolute hierarchy path
        self.children = []
    # tag: str
    # attrib: dict
    # name: str | None = None
    # text: str | None = None
    # children: list = field(default_factory=list)
    # path: str = ""

    def add_child(self, child):
        self.children.append(child)

    def __repr__(self):
        return f"<ElementNode tag={self.tag} path={self.path}>"

from dataclasses import dataclass

@dataclass
class MergeConflict:
    path: str
    conflict_type: str
    details: str

class IncompatibleMergeError(Exception):
    pass

def extract_element_name(attrib):
    """
    Returns the semantic 'name' of an element if present.
    """
    for key in attrib:
        if key.endswith("name"):
            return attrib[key]
    return None

def log(msg, level, current_level):
    """
    level: required verbosity for this message
    current_level: user-selected verbosity
    """
    if current_level >= level:
        print(msg)

def check_node_compatibility(
    node_a,
    node_b,
    report=None,
    strict=True,
    log_level=0,
):
    log(
        f"Checking compatibility: {node_a.path}",
        2,
        log_level,
    )

    compatible = True
    path = node_a.path

    def conflict(kind, msg):
        nonlocal compatible
        compatible = False
        log(
            f"Incompatibility at {path}: {kind} – {msg}",
            1,
            log_level,
        )
        if report:
            report.add(path, kind, msg)
        if strict:
            raise IncompatibleMergeError(msg)

    # Text vs children
    if (node_a.text and node_a.children) or (node_b.text and node_b.children):
        conflict("text+children", "Node has both text and children")

    if (node_a.text and node_b.children) or (node_b.text and node_a.children):
        conflict("text-vs-children", "Text/children mismatch")

    # Attributes
    all_attrs = set(node_a.attrib) | set(node_b.attrib)
    for attr in all_attrs:
        a_has = attr in node_a.attrib
        b_has = attr in node_b.attrib

        if a_has != b_has:
            conflict(
                "attribute-presence",
                f"Attribute '{attr}' present in one node only",
            )
        elif node_a.attrib[attr] != node_b.attrib[attr]:
            conflict(
                "attribute-value",
                f"{attr}='{node_a.attrib[attr]}' vs '{node_b.attrib[attr]}'",
            )

    # Child structure
    a_children = {c.tag for c in node_a.children}
    b_children = {c.tag for c in node_b.children}

    if a_children != b_children:
        conflict(
            "child-structure",
            f"{a_children} vs {b_children}",
        )

    return compatible

# def extract_namespaces(xml_or_xsd_file):
#     """
#     Extract namespace declarations from an XML/XSD file.

#     Returns:
#         dict: {prefix: uri}
#         prefix is '' for default namespace
#     """
#     namespaces = {}
#     for event, elem in ET.iterparse(xml_or_xsd_file, events=("start-ns",)):
#         prefix, uri = elem
#         namespaces[prefix or "default"] = uri
#     return namespaces

def extract_namespaces_from_file(file_path, log_level=0):
    namespaces = {}
    for event, elem in ET.iterparse(file_path, events=("start-ns",)):
        prefix, uri = elem
        namespaces[prefix or "default"] = uri
        log(
            f"Namespace detected: prefix='{prefix}', uri='{uri}'",
            2,
            log_level,
        )
    return namespaces

def collect_unique_tags(xml_file):
    """
    First pass: iterate once and collect all unique tag names.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    unique_tags = set()
    for elem in root.iter():
        unique_tags.add(elem.tag)

    return unique_tags

# def node_signature(node):
#     """
#     Unique structural signature for deduplication.
#     """
#     return (node.tag, node.path)

def node_signature(node: ElementNode):
    """
    Uniquely identifies a node for deduplication.
    """
    return (
        node.tag,
        node.name,  # ← NEW
        tuple(sorted(node.attrib.keys())),
        tuple(sorted(child.tag for child in node.children)),
    )

def build_element_tree(element, parent_path=""):
    """
    Second pass: recursively build ElementNode objects
    while preserving hierarchy.
    """
    current_path = f"{parent_path}/{element.tag}" if parent_path else element.tag
    name = extract_element_name(element.attrib)

    node = ElementNode(
        tag=element.tag,
        attrib=element.attrib,
        text=element.text,
        path=current_path,
        name=name
    )

    for child in element:
        child_node = build_element_tree(child, current_path)
        node.add_child(child_node)

    return node

# def parse_xml_with_hierarchy(xml_file):
#     """
#     Performs:
#     1) Namespace extraction
#     2) Collect unique tags
#     3) Build hierarchy-aware object tree
#     """
#     namespaces = extract_namespaces(xml_file)
#     unique_tags = collect_unique_tags(xml_file)

#     tree = ET.parse(xml_file)
#     root = tree.getroot()
#     hierarchy_root = build_element_tree(root)

#     return namespaces, unique_tags, hierarchy_root

def parse_xml_with_hierarchy(file_path, log_level=0):
    """
    Parses XML into:
      - namespaces
      - set of unique tags
      - ElementNode hierarchy
    """

    log(f"Parsing XML file: {file_path}", 1, log_level)

    namespaces = extract_namespaces_from_file(file_path, log_level)
    log(f"Total namespaces: {len(namespaces)}", 1, log_level)

    tree = ET.parse(file_path)
    root = tree.getroot()

    unique_tags = set()

    def build_node(elem, parent_path=""):
        #tag = elem.tag.split("}")[-1]  # strip namespace
        tag=elem.tag
        path = f"{parent_path}/{tag}" if parent_path else tag

        unique_tags.add(tag)

        name = extract_element_name(elem.attrib)

        #log(f"Visiting element: {path}", 2, log_level)
        log(
            f"Visiting element: {path}"
            + (f" [name={name}]" if name else ""),
            2,
            log_level,
        )

        # node = ElementNode(
        #     tag=tag,
        #     attrib=dict(elem.attrib),
        #     text=(elem.text.strip() if elem.text and elem.text.strip() else None),
        #     path=path,
        # )
        node = ElementNode(
            tag=tag,
            attrib=dict(elem.attrib),
            name=name,
            text=(elem.text.strip() if elem.text and elem.text.strip() else None),
            path=path,
        )

        for child in elem:
            child_node = build_node(child, path)
            node.children.append(child_node)

        return node

    root_node = build_node(root)

    log(
        f"XML parsed. Unique tags found: {len(unique_tags)}",
        1,
        log_level,
    )

    return namespaces, unique_tags, root_node

class MergeReport:
    def __init__(self, log_level=0):
        self.conflicts = []
        self.log_level = log_level
        log("Initialized MergeReport", 2, self.log_level)

    def add(self, path, conflict_type, details):
        self.conflicts.append(
            MergeConflict(path, conflict_type, details)
        )
        log(
            f"[CONFLICT] {path} | {conflict_type} | {details}",
            1,
            self.log_level,
        )

    def has_conflicts(self):
        return bool(self.conflicts)

    
# def merge_nodes(node_a, node_b):
#     """
#     Merge two ElementNode objects recursively.
#     node_a is treated as the base.
#     """

#     # Merge attributes
#     merged_attrib = dict(node_a.attrib)
#     for k, v in node_b.attrib.items():
#         if k not in merged_attrib:
#             merged_attrib[k] = v

#     # Merge text
#     merged_text = node_a.text or node_b.text

#     merged = ElementNode(
#         tag=node_a.tag,
#         attrib=merged_attrib,
#         text=merged_text,
#         path=node_a.path,
#     )

#     # Index children by signature
#     children_map = {}

#     for child in node_a.children:
#         children_map[node_signature(child)] = child

#     for child in node_b.children:
#         sig = node_signature(child)
#         if sig in children_map:
#             children_map[sig] = merge_nodes(children_map[sig], child)
#         else:
#             children_map[sig] = child

#     merged.children = list(children_map.values())
#     return merged

def merge_nodes(
    node_a,
    node_b,
    report=None,
    strict=True,
    log_level=0,
):
    log(f"Merging node: {node_a.path}", 2, log_level)

    compatible = check_node_compatibility(
        node_a,
        node_b,
        report=report,
        strict=strict,
        log_level=log_level,
    )

    if not compatible:
        log(
            f"Preserving base node due to incompatibility: {node_a.path}",
            1,
            log_level,
        )
        return node_a

    # merged = ElementNode(
    #     tag=node_a.tag,
    #     attrib=dict(node_a.attrib),
    #     text=node_a.text or node_b.text,
    #     path=node_a.path,
    # )
    merged = ElementNode(
        tag=node_a.tag,
        attrib=dict(node_a.attrib),
        name=node_a.name or node_b.name,
        text=node_a.text or node_b.text,
        path=node_a.path,
    )


    children_map = {node_signature(c): c for c in node_a.children}
    
    if node_a.name != node_b.name:
        report.conflicts(
        "name-mismatch",
        f"{node_a.name} vs {node_b.name}",
    )
        
    for child in node_b.children:
        sig = node_signature(child)
        if sig in children_map:
            children_map[sig] = merge_nodes(
                children_map[sig],
                child,
                report=report,
                strict=strict,
                log_level=log_level,
            )
        else:
            log(
                f"Adding new child {child.tag} at {node_a.path}",
                2,
                log_level,
            )
            children_map[sig] = child

    merged.children = list(children_map.values())
    return merged

def indent(elem, level=0, indent_str="  "):
    """
    In-place pretty formatting for ElementTree elements.
    """
    i = "\n" + level * indent_str

    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + indent_str

        for child in elem:
            indent(child, level + 1, indent_str)

        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i

# def combine_with_file(
#     base_namespaces,
#     base_tags,
#     base_root_node,
#     new_file,
# ):
#     """
#     Parse a new XML/XSD file and merge its structure with the existing one.

#     Returns:
#         combined_namespaces
#         combined_tags
#         combined_root_node
#     """

#     # --- parse the new file ---
#     new_namespaces = extract_namespaces(new_file)
#     new_tags = collect_unique_tags(new_file)

#     tree = ET.parse(new_file)
#     new_root = tree.getroot()
#     new_root_node = build_element_tree(new_root)

#     # --- merge namespaces ---
#     combined_namespaces = dict(base_namespaces)
#     for k, v in new_namespaces.items():
#         if k not in combined_namespaces:
#             combined_namespaces[k] = v

#     # --- merge tags ---
#     combined_tags = set(base_tags) | set(new_tags)

#     # --- merge hierarchy ---
#     if base_root_node.tag != new_root_node.tag:
#         raise ValueError(
#             f"Root mismatch: {base_root_node.tag} vs {new_root_node.tag}"
#         )

#     combined_root_node = merge_nodes(base_root_node, new_root_node)

#     return combined_namespaces, combined_tags, combined_root_node

def combine_with_file(
    base_namespaces,
    base_tags,
    base_root_node,
    new_file,
    strict=False,
    report=None,
    log_level=0,
):
    log(f"Combining file: {new_file}", 1, log_level)

    if report is None:
        report = MergeReport(log_level=log_level)

    new_namespaces = extract_namespaces_from_file(new_file)
    new_tags = collect_unique_tags(new_file)

    log(
        f"Namespaces found: {new_namespaces}",
        2,
        log_level,
    )
    log(
        f"New tags discovered: {len(new_tags)}",
        2,
        log_level,
    )

    tree = ET.parse(new_file)
    new_root = tree.getroot()
    new_root_node = build_element_tree(new_root)

    combined_namespaces = dict(base_namespaces)
    # for k, v in new_namespaces.items():
    #     combined_namespaces.setdefault(k, v)
    for k, v in new_namespaces.items():
        if k not in combined_namespaces:
            combined_namespaces[k] = v

    combined_tags = set(base_tags) | set(new_tags)

    if base_root_node.tag != new_root_node.tag:
        msg = f"{base_root_node.tag} vs {new_root_node.tag}"
        report.add("", "root-mismatch", msg)
        if strict:
            raise IncompatibleMergeError(msg)

    combined_root = merge_nodes(
        base_root_node,
        new_root_node,
        report=report,
        strict=strict,
        log_level=log_level,
    )

    return combined_namespaces, combined_tags, combined_root, report

def write_merge_report(report, output_file, log_level=0):
    log(f"Writing merge report to {output_file}", 1, log_level)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("XML MERGE REPORT\n")
        f.write("=" * 50 + "\n\n")

        if not report.conflicts:
            f.write("No conflicts detected.\n")
            return

        for i, c in enumerate(report.conflicts, 1):
            f.write(f"{i}. Path: {c.path}\n")
            f.write(f"   Type: {c.conflict_type}\n")
            f.write(f"   Details: {c.details}\n\n")

def elementnode_to_etree(node):
    """
    Convert an ElementNode back into an ElementTree Element recursively.
    """
    elem = ET.Element(node.tag, attrib=node.attrib)

    if node.text:
        elem.text = node.text

    for child in node.children:
        elem.append(elementnode_to_etree(child))

    return elem

def validate_written_xml(xml_file):
    """
    Validate written XML by re-parsing it.
    Ensures well-formedness and structural integrity.
    """
    try:
        ET.parse(xml_file)
    except ET.ParseError as e:
        raise ValueError(f"XML validation failed: {e}") from e

def write_combined_xml(
    root_node,
    namespaces,
    output_file,
    xml_declaration=True,
    encoding="utf-8",
    indent_str="  ",
):
    """
    Write the combined ElementNode tree to disk, pretty-printed and validated.
    """

    # Register namespaces
    for prefix, uri in namespaces.items():
        if prefix == "default":
            ET.register_namespace("", uri)
        else:
            ET.register_namespace(prefix, uri)

    # Convert ElementNode → ElementTree
    root_elem = elementnode_to_etree(root_node)

    # Pretty-print in-place
    indent(root_elem, indent_str=indent_str)

    tree = ET.ElementTree(root_elem)

    # Write file
    tree.write(
        output_file,
        encoding=encoding,
        xml_declaration=xml_declaration,
    )

    # Validate after writing
    validate_written_xml(output_file)

    return output_file

# if __name__ == "__main__":
#     os.chdir('.\\XSD_combine')
#     ns, tags, root_node = parse_xml_with_hierarchy("49571382423_8b6d54f3ef_o.jpg.xsd")

#     print("Unique tags:")
#     for t in sorted(tags):
#         print(" ", t)

#     print("\nRoot node:")
#     print(root_node)
# Parse first file
log_level=2
os.chdir('.\\Sample')
namespaces, tags, root_node = parse_xml_with_hierarchy("49571382423_8b6d54f3ef_o.jpg.xsd",log_level=log_level)

# Merge second file
namespaces, tags, root, report = combine_with_file(
    namespaces,
    tags,
    root_node,
    "49571382018_cf92c9ab47_o.jpg.xsd",log_level=log_level
)

print("Namespaces:", namespaces)
print("Tags:", tags)
print("Root path:", root_node.path)
write_combined_xml(root_node=root_node,namespaces=namespaces,output_file="flickr_photo_schema.xsd")
write_merge_report(report, "merge_report.txt",log_level=log_level)