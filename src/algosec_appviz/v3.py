"""
AlgoSec AppViz REST API v3 client -- "Applications" tag.

Generated from the AppViz v3 OpenAPI spec. Server path: /appviz
(e.g. https://eu.app.algosec.com/appviz).

This class shares only the auth logic with AppViz (v2), via the
AppVizAuth base class -- it has its own request helpers (_get, _post,
_delete) and is used standalone, with its own login:

    from algosec_appviz import AppVizV3
    inst = AppVizV3()
    apps = inst.list_applications()

Note from the spec's description:
    "Unless otherwise specified on the specific API, the APIs are currently
    in Early Access and might change in the future. AlgoSec does not
    provide any operational support or SLA around these Early Availability
    APIs."

Endpoints covered (all under tag "Applications"):
    GET    /rest/v3/applications                              list_applications
    GET    /rest/v3/applications/{appId}                       get_application
    DELETE /rest/v3/applications/{appId}                       delete_application
    GET    /rest/v3/applications/{appId}/revisions             get_visible_revisions
    POST   /rest/v3/applications/{id}/actions/resolve          resolve_application
    POST   /rest/v3/applications/{id}/actions/recertify        recertify_application
    POST   /rest/v3/applications/{id}/actions/decommission     decommission_application
    POST   /rest/v3/applications/{id}/actions/activate         activate_application
    POST   /rest/v3/applications/{id}/action                   application_action
    POST   /rest/v3/applications/search                        search_applications
    POST   /rest/v3/applications/search/actions/export/csv     export_search_results_to_csv
    POST   /rest/v3/applications/actions/export/csv             export_applications_to_csv

All POST "actions" and the search endpoint are asynchronous -- they return
a RestTask (202) that you poll via the Tasks API
(GET /rest/v3/tasks/{taskId}, not included here -- flag if you want it added).
"""

import logging
import os

import requests

from .auth import AppVizAuth
from .environment import VERBOSE, DEBUG

logger = logging.getLogger(__name__)


class AppVizV3(AppVizAuth):
    """
    AlgoSec AppViz REST API v3 client (Applications endpoints).

    Usage:
        from algosec_appviz import AppVizV3
        inst = AppVizV3()
        inst.list_applications()
    """

    #: Fields selectable via the `fields` query param on list/export
    #: endpoints, per the spec's parameter description.
    OPTIONAL_FIELDS = (
        "revisionStatus", "connectivityStatus", "lifecyclePhase",
        "lastRecertificationDate", "lastRecertifiedBy",
        "recertificationInProgress", "vulnerabilityScore", "expirationDate",
        "locked", "tags", "dashboardUrl", "tags.id", "tags.name",
        "cloudApplication.id", "cloudApplication.accountId",
        "cloudApplication.provider", "revisionsCount",
        "recertifiedFlowsCount",
    )

    def __init__(self, region='eu', tenant_id=None, client_id=None,
                 client_secret=None, proxies=None, verify_ssl=True, timeout=30):
        super().__init__(region=region, tenant_id=tenant_id, client_id=client_id,
                         client_secret=client_secret, proxies=proxies)

        self.timeout = timeout
        self.base_url = f"{self.url}/appviz/rest/v3"

        # v3 gets its own session, independent of anything v2 does.
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.proxies = proxies or {}
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self.session.headers["Authorization"] = self._auth_header

    # ------------------------------------------------------------------ #
    # Own request helpers (not shared with AppViz/v2)
    # ------------------------------------------------------------------ #

    def _request(self, method, path, **kwargs):
        # Refresh token if needed and keep the session header in sync.
        self.session.headers["Authorization"] = self._auth_header
        url = f"{self.base_url}{path}"
        kwargs.setdefault("timeout", self.timeout)
        response = self.session.request(method, url, **kwargs)
        if DEBUG:
            print(f"_request response: {response}")
        response.raise_for_status()
        return response

    def _get(self, path, params=None):
        resp = self._request("GET", path, params=params)
        if DEBUG:
            print(f"_request response: {resp}")

        return resp.json() if resp.content else None

    def _post(self, path, json_body=None, params=None):
        resp = self._request("POST", path, json=json_body, params=params)
        if DEBUG:
            print(f"_request response: {resp}")

        return resp.json() if resp.content else None

    def _delete(self, path):
        resp = self._request("DELETE", path)
        if DEBUG:
            print(f"_request response: {resp}")

        return resp.json() if resp.content else None

    # ------------------------------------------------------------------ #
    # GET /applications  -- listApplications
    # ------------------------------------------------------------------ #

    def list_applications(self, page=0, size=100, sort=('id,ASC',),
                          fields=None, filter=None, count_total_elements=None):
        """
        List applications.

        :param page: Zero-based page index (default 0).
        :param size: Page size (default 10).
        :param sort: Sort spec(s), e.g. ["id,ASC"] (default).
        :param fields: Which fields to include. Always includes "id".
            Default fields: id, name, revisionId, riskScore, updatedAt,
            flowsCount. Other options: see OPTIONAL_FIELDS.
        :param filter: SQL "WHERE"-like filter string, e.g. "name = 'MyApp'".
            Filterable fields: id, name, updatedAt, expirationDate,
            lastRecertifiedBy, lifecyclePhase, cloudApplication.accountId,
            cloudApplication. provider, revisionStatus, tags.id, tags.name.
        :param count_total_elements: If True, returns RestApplicationPage
            (includes total count/pages). If False/omitted, returns the
            more performant RestApplicationSimplePage.
        :return: dict -- RestApplicationPage or RestApplicationSimplePage.
        """
        params = {"page": page, "size": size, "sort": list(sort)}
        if fields is not None:
            params["fields"] = list(fields)
        if filter is not None:
            params["filter"] = filter
        if count_total_elements is not None:
            params["countTotalElements"] = count_total_elements
        return self._get("/applications", params=params)

    def get_all_applications(self):
        all_apps = []
        page = 0

        while True:
            if VERBOSE:
                print(f"Getting applications, page {page + 1}...")
            result = self.list_applications(page=page, size=500)
            all_apps.extend(result['elements'])
            page += 1

            if not result['next']:
                break

        return all_apps

    # ------------------------------------------------------------------ #
    # GET /applications/{appId}  -- getApplication
    # ------------------------------------------------------------------ #

    def get_application(self, app_id):
        """Get data for a specific application, based on its head revision."""
        return self._get(f"/applications/{app_id}")

    # ------------------------------------------------------------------ #
    # DELETE /applications/{appId}  -- applicationDelete
    # ------------------------------------------------------------------ #

    def delete_application(self, app_id):
        """
        Delete a decommissioned application.
        :return: dict -- RestTask describing the delete operation.
        """
        return self._delete(f"/applications/{app_id}")

    # ------------------------------------------------------------------ #
    # GET /applications/{appId}/revisions  -- getVisibleRevisions
    # ------------------------------------------------------------------ #

    def get_visible_revisions(self, app_id):
        """Get the (visible) revisions of an application."""
        return self._get(f"/applications/{app_id}/revisions")

    # ------------------------------------------------------------------ #
    # POST /applications/{id}/actions/resolve  -- resolveApplication
    # ------------------------------------------------------------------ #

    def resolve_application(self, app_id, subject=None):
        """
        Start an asynchronous "resolve" action on an application
        (e.g. resolving blocked connectivity).
        :param app_id: Application ID
        :param subject: Subject line for the generated change request.
        :return: dict -- RestTask (background task handle) on success (202).
        """
        payload = {}
        if subject is not None:
            payload["subject"] = subject
        return self._post(f"/applications/{app_id}/actions/resolve", json_body=payload)

    # ------------------------------------------------------------------ #
    # POST /applications/{id}/actions/recertify  -- recertifyApplication
    # ------------------------------------------------------------------ #

    def recertify_application(self, app_id, recertification_comment):
        """
        Start an asynchronous re-certification action on an application.
        :param app_id: Application ID
        :param recertification_comment: Required, non-empty comment.
        :return: dict -- RestTask on success (202).
        """
        payload = {"recertificationComment": recertification_comment}
        return self._post(f"/applications/{app_id}/actions/recertify", json_body=payload)

    # ------------------------------------------------------------------ #
    # POST /applications/{id}/actions/decommission  -- decommissionApplication
    # ------------------------------------------------------------------ #

    def decommission_application(self, app_id, subject=None):
        """
        Start an asynchronous decommission action on an application.
        :param app_id: Application ID
        :param subject: Subject line for the generated decommission change request.
        :return: dict -- RestTask on success (202).
        """
        payload = {}
        if subject is not None:
            payload["subject"] = subject
        return self._post(f"/applications/{app_id}/actions/decommission", json_body=payload)

    # ------------------------------------------------------------------ #
    # POST /applications/{id}/actions/activate  -- activateApplication
    # ------------------------------------------------------------------ #

    def activate_application(self, app_id, subject=None, selected_flow_ids=None,
                             avoid_change_request=False):
        """
        Start an asynchronous activation action on an application.
        :param app_id: Application ID
        :param subject: Subject for the change request. Required unless
            avoid_change_request=True.
        :param selected_flow_ids: Flow IDs to activate. Omit to activate all flows.
        :param avoid_change_request: If True, no change request is created.
        :return: dict -- RestTask on success (202).
        """
        payload = {"avoidChangeRequest": avoid_change_request}
        if subject is not None:
            payload["subject"] = subject
        if selected_flow_ids is not None:
            payload["selectedFlowsIds"] = list(selected_flow_ids)
        return self._post(f"/applications/{app_id}/actions/activate", json_body=payload)

    # ------------------------------------------------------------------ #
    # POST /applications/{id}/action  -- applicationActions
    # ------------------------------------------------------------------ #

    def application_action(self, app_id, action_type, payload=None):
        """
        Generic background action endpoint (per the spec, currently used
        for re-certification via a typed envelope).
        :param app_id: Application ID
        :param action_type: Value for the "type" field of the request envelope.
        :param payload: Action-specific payload dict, e.g.
            {"recertificationComment": "..."} for a recertify action.
        :return: dict -- RestTask on success (202).
        """
        body = {"type": action_type, "payload": payload or {}}
        return self._post(f"/applications/{app_id}/action", json_body=body)

    # ------------------------------------------------------------------ #
    # POST /applications/search  -- searchApplications
    # ------------------------------------------------------------------ #

    def search_applications(self, search_filter, page=0, size=10, sort=()):
        """
        Perform an advanced search on Applications (runs in the background).
        :param page: Page number (default 0).
        :param size: Page size (default 10).
        :param search_filter: RestApplicationSearchFilter dict, e.g.
            {
                "fromExpirationDate": "2024-01-01T00:00:00Z",
                "toExpirationDate": "2024-12-31T23:59:59Z",
                "projects": [123],
                "connectivityList": ["Blocked", "Partial"],
                "revisionStatusList": ["ACTIVE", "DRAFT"],
                ...
            }
        :param page, size, sort: Pageable params (query string).
        :return: dict -- RestTask -- poll the Tasks API for the search results.
        """
        params = {"page": page, "size": size}
        if sort:
            params["sort"] = list(sort)
        return self._post("/applications/search", json_body=search_filter, params=params)

    # ------------------------------------------------------------------ #
    # POST /applications/search/actions/export/csv
    # -- exportApplicationsAdvancedSearchResultsToCsv
    # ------------------------------------------------------------------ #

    def export_search_results_to_csv(self, export_request):
        """
        Start a background export-to-CSV of an applications advanced
        search (ExportAdvancedSearchResultsRequest body -- same shape as
        the search filter used in search_applications, plus any export
        options defined by the schema).
        :return: dict -- RestTask -- poll the Tasks API for the resulting file.
        """
        return self._post("/applications/search/actions/export/csv",
                          json_body=export_request)

    # ------------------------------------------------------------------ #
    # POST /applications/actions/export/csv  -- exportApplicationsListToCsv
    # ------------------------------------------------------------------ #

    def export_applications_to_csv(self, fields=None, filter=None):
        """
        Start a background export-to-CSV of the applications list.
        :param fields: Same semantics as in list_applications().
        :param filter: Same SQL "WHERE"-like filter as in list_applications().
        :return: dict -- RestTask -- poll the Tasks API for the resulting file.
        """
        params = {}
        if fields is not None:
            params["fields"] = list(fields)
        if filter is not None:
            params["filter"] = filter
        return self._post("/applications/actions/export/csv", params=params or None)

    def get_task(self, task_id=None):
        """
        Get a task by ID
        :param task_id: Task ID.
        """
        if task_id is None:
            raise ValueError("task_id is required")

        return self._get(f"/tasks/{task_id}")

    def list_group_members(self, group_id=None):
        """
        List the members of a group network object. This works also for other type of objects
        :param group_id: Object ID.
        """
        if group_id is None:
            raise ValueError("group_id is required")

        result = self._get(f"/network-objects/{group_id}/items", params={'size': 100})
        if result['elements']:
            return result['elements']

        return None
