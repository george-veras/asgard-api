from typing import Dict, Union, List, Any, Optional, Set
from collections import defaultdict
from decimal import Decimal, ROUND_UP
from asgard.backends.base import Backend

from asgard.sdk import mesos
from asgard.math import round_up
from asgard.http.client import http_client


from asgard.services.models.agent import Agent
from asgard.services.models.app import App
from asgard.services.models.task import Task


class MesosTask(Task):
    _type: str = "MESOS"
    typer: str = "MESOS"

    name: str

    def transform_to_asgard_task_id(executor_id: str) -> str:
        task_name_part = executor_id.split("_")[1:]
        return "_".join(task_name_part)


class MesosApp(App):
    _type: str = "MESOS"
    type: str = "MESOS"
    id: str

    def transform_to_asgard_app_id(executor_id: str) -> str:
        task_name_part = executor_id.split(".")[0]
        return "/".join(task_name_part.split("_")[1:])


class MesosAgent(Agent):
    _type: str = "MESOS"
    type: str = "MESOS"
    id: str
    hostname: str
    active: bool
    version: str
    port: int
    used_resources: Dict[str, Union[str, int]]
    attributes: Dict[str, str]
    resources: Dict[str, Union[str, int]]
    total_apps: int = 0
    applications: List[MesosApp] = []
    stats: Optional[Dict[str, Any]] = {}

    def filter_by_attrs(self, kv):
        pass

    async def calculate_stats(self):
        """
        Calculate usage statistics.
            - CPU % usage
            - RAM % usage
        """
        cpu_pct = (
            Decimal(self.used_resources["cpus"])
            / Decimal(self.resources["cpus"])
            * 100
        )

        ram_pct = (
            Decimal(self.used_resources["mem"])
            / Decimal(self.resources["mem"])
            * 100
        )

        self.stats = {
            "cpu_pct": str(round_up(cpu_pct)),
            "ram_pct": str(round_up(ram_pct)),
        }

    async def apps(self) -> List[App]:
        self_address = f"http://{self.hostname}:{self.port}"
        containers_url = f"{self_address}/containers"
        apps = []
        async with http_client.get(containers_url) as response:
            data = await response.json()
            all_apps: Set[str] = set()
            for container_info in data:
                app_id = MesosApp.transform_to_asgard_app_id(
                    container_info["executor_id"]
                )
                if app_id not in all_apps:
                    apps.append(MesosApp(**{"id": app_id}))
                    all_apps.add(app_id)
            return apps

    async def tasks(self, app_id: str) -> List[Task]:
        self_address = f"http://{self.hostname}:{self.port}"
        containers_url = f"{self_address}/containers"
        async with http_client.get(containers_url) as response:
            data = await response.json()
            tasks_per_app: Dict[str, List[MesosTask]] = defaultdict(list)
            for container_info in data:
                app_id_ = MesosApp.transform_to_asgard_app_id(
                    container_info["executor_id"]
                )
                tasks_per_app[app_id_].append(
                    MesosTask(
                        **{
                            "name": MesosTask.transform_to_asgard_task_id(
                                container_info["executor_id"]
                            )
                        }
                    )
                )
            return tasks_per_app[app_id]


class MesosBackend(Backend):
    async def populate_apps(self, agent):
        try:
            agent.applications = await agent.apps()
            agent.total_apps = len(agent.applications)
        except Exception as e:
            agent.add_error(field_name="total_apps", error_msg="INDISPONIVEL")

    async def get_agents(
        self, namespace: str, attr_filters: Dict[str, Any] = {}
    ) -> List[MesosAgent]:
        mesos_leader_address = await mesos.leader_address()
        agents_url = f"{mesos_leader_address}/slaves"
        async with http_client.get(agents_url) as response:
            filtered_agents = []
            data = await response.json()
            for agent_dict in data["slaves"]:
                mesos_agent = MesosAgent(**agent_dict)
                if not mesos_agent.attr_has_value("owner", namespace):
                    continue
                await self.populate_apps(mesos_agent)
                await mesos_agent.calculate_stats()
                filtered_agents.append(mesos_agent)
        return filtered_agents

    async def get_agent_by_id(
        self, namespace: str, agent_id: str
    ) -> Optional[Agent]:
        mesos_leader_address = await mesos.leader_address()
        agent_url = f"{mesos_leader_address}/slaves?slave_id={agent_id}"
        async with http_client.get(agent_url) as response:
            data = await response.json()
            if len(data["slaves"]):
                agent = MesosAgent(**data["slaves"][0])
                if not agent.attr_has_value("owner", namespace):
                    return None

                await self.populate_apps(agent)
                await agent.calculate_stats()
                return agent
            return None

    async def get_apps(self, namespace: str, agent_id: str) -> List[App]:
        agent = await self.get_agent_by_id(namespace, agent_id)
        if agent:
            return agent.applications
        return []

    async def get_tasks(
        self, namespace: str, agent_id: str, app_id: str
    ) -> List[Task]:
        pass
