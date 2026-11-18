from diagrams import Cluster, Diagram, Edge
from diagrams.onprem.network import Internet
from diagrams.oci.compute import Container, Functions
from diagrams.oci.database import Science
from diagrams.oci.monitoring import Events
from diagrams.oci.storage import Buckets
from diagrams.onprem.vcs import Github
from diagrams.saas.cdn import Akamai
from diagrams.onprem.client import Users

graph_attr = {"pad": "0.4", "nodesep": "0.7", "ranksep": "1.2", "fontsize": "16", "splines": "spline", "newrank": "true"}

with Diagram(
    "",
    filename="deployment-architecture",
    outformat="png",
    show=False,
    direction="LR",
    graph_attr=graph_attr,
):
    advisories = Internet("Advisory sources\nGLSA, OSV, kernel,\noss-security")

    with Cluster("Oracle Cloud (OCI)"):
        sched = Events("Scheduler")
        with Cluster("Jobs (containers or small VMs)"):
            triage = Container("Triage job")
            pkgs = Container("Package update job")
            release = Container("Release job\n(per release)")
        llm = Science("LLMs\n(OCI hosted)")
        raw = Buckets("Raw fetches\n(advisories, SBOMs)")
        store = Buckets("Findings and\ndecisions")
        public = Buckets("Public VEX and\nrelease notes")

    with Cluster("GitHub"):
        repo = Github("Review issues, decisions repo\nand package PRs")

    edge = Akamai("Akamai CDN\n(optional)")
    users = Users("Users and\nsecurity teams")

    sched >> [triage, pkgs]
    advisories >> triage
    triage >> raw
    triage >> Edge(label="prompts") >> llm
    triage >> store
    triage >> Edge(label="review") >> repo
    pkgs >> repo
    repo >> Edge(label="approved") >> store
    store >> release >> public >> edge >> users
