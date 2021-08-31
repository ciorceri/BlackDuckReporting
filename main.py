import sys
import csv
import requests
import argparse
import blackduck

DEBUG = False
csv_header = ['Repository', 'Component', 'Timestamp', 'DependencyType', 'Version', 'LicenseRisk', 'SecurityRisk',
              'VersionRisk', 'ActivityRisk', 'OperationalRisk', 'VulnerabilityId', 'Description', 'Url', 'Solution']
''' Dependency types:
    FILE_DEPENDENCY_DIRECT : 'Direct Dependency'
    FILE_DEPENDENCY_TRANSITIVE : 'Transitive Dependency'
    FILE_EXACT : 'Exact Directory'
'''


class ArgumentParser(object):
    """
    Parses the parameters from command line
    """

    def __init__(self):
        self.parser = argparse.ArgumentParser(description="BlackDuck reporting")
        self.parser.add_argument("-b", "--baseurl", type=str, required=True, help="Url to BlackDuck server")
        self.parser.add_argument("-t", "--token", type=str, required=True,
                                 help="Token used to connect to BlackDuck server")
        self.parser.add_argument("-v", "--version", type=str, required=False, default="master",
                                 help="Project version to scan")
        self.parser.add_argument("-f", "--filterproject", type=str, required=False, default="",
                                 help="Filter project names")

    def parse(self, args):
        return self.parser.parse_args(args)


def build_csv_row(repository: str = '', component: str = '', timestamp: str = '', dep_type: str = '', version: str = '',
                  license_risk: str = '', security_risk: str = '', version_risk: str = '', activity_risk: str = '',
                  operational_risk: str = '', vulnerability_id: str = '', description: str = '', url: str = '',
                  solution: str = ''):
    """
    :param repository: repository name
    :param component: component/library name
    :param timestamp: component scan date/time
    :param dep_type: component dependency type (direct, transitive, exact)
    :param version: used version
    :param license_risk
    :param security_risk
    :param version_risk
    :param activity_risk
    :param operational_risk
    :param vulnerability_id: the CVE, BDSA id
    :param description: vulnerability description
    :param url: vulnerability URL
    :param solution: update to version
    :return: a list with parameters
    """
    row = [repository, component, timestamp, dep_type, version, license_risk, security_risk, version_risk,
           activity_risk, operational_risk, vulnerability_id, description, url, solution]
    return row


def _get_all_risks(risk):
    """
    called by build_risk() to get all risks in a friendly string
    """
    risk_filtered = list(filter(lambda x: x['count'] > 0, risk))
    risk_str = ','.join(map(lambda x: x['countType'], risk_filtered))
    return risk_str


def _get_highest_risk(risk):
    """
    called by build_risk() to get the highest security risk as string
    """
    risk_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'OK']
    for ro in risk_order:
        for r in risk:
            if r['countType'] == ro and r['count']:
                return ro
    return ''


def build_risk(dict_input: dict):
    """
    :param dict_input:
    :return: Will return a tuple (of 5) with : LicenseRisk SecurityRisk VersionRisk ActivityRisk OperationalRisk
    """
    license_risk = dict_input['licenseRiskProfile']['counts']
    license_risk_str = _get_highest_risk(license_risk)

    security_risk = dict_input['securityRiskProfile']['counts']
    security_risk_str = _get_highest_risk(security_risk)

    version_risk = dict_input['versionRiskProfile']['counts']
    version_risk_str = _get_highest_risk(version_risk)

    activity_risk = dict_input['activityRiskProfile']['counts']
    activity_risk_str = _get_highest_risk(activity_risk)

    operational_risk = dict_input['operationalRiskProfile']['counts']
    operational_risk_str = _get_highest_risk(operational_risk)

    return license_risk_str, security_risk_str, version_risk_str, activity_risk_str, operational_risk_str


def build_vulnerability(dict_input: dict):
    for item in dict_input['items']:
        yield item['name'].strip()


def build_vulnerability_description(dict_input: dict):
    for item in dict_input['items']:
        yield item['description'].replace('\n', ' ').strip()


def build_vulnerability_url(dict_input: dict):
    for item in dict_input['items']:
        yield item['_meta']['href'].strip()


def build_solution(dict_input: dict):
    short_term = dict_input.get('shortTerm', '-')
    if short_term != '-':
        short_term = short_term.get('versionName', '-').strip()
    long_term = dict_input.get('longTerm', '-')
    if long_term != '-':
        long_term = long_term.get('versionName', '-').strip()
    solution = 'Short-term:{}, Long-term:{}'.format(short_term, long_term)
    return solution


def main():
    args = ArgumentParser().parse(sys.argv[1:])

    bd = blackduck.Client(
        token=args.token,
        base_url=args.baseurl,
        verify=False,  # setto True for production
        timeout=180,
        retries=10
    )
    csv_writer = csv.writer(sys.stdout, lineterminator='\n')
    csv_writer.writerow(csv_header)

    for project in bd.get_resource(name='projects'):
        for version in bd.get_resource('versions', project):
            # filter based on the project name (default : get all projects)
            if not args.filterproject in project['name']:
                continue
            # filter only reports for a specific version (default : use only 'master' version)
            if args.version == version['versionName']:
                project_version_resources = bd.list_resources(version)
                # on some reports I don't have read access so I will not see the components => skip them
                if 'components' not in project_version_resources.keys():
                    continue
                components_generator = bd.get_items(project_version_resources['components'])
                for component in components_generator:
                    scan_date = component['releasedOn']
                    dep_type = component['matchTypes']
                    dep_type_normalised = ','.join(dep_type)
                    vuln = bd.get_resource(name='vulnerabilities', parent=component, items=False)
                    vuln_count = vuln['totalCount']
                    try:
                        # sometimes we cannot get the 'solution' and we have a 404 HTTPError
                        upgrade_guidance = bd.get_resource(name='upgrade-guidance', parent=component, items=False)
                    except requests.exceptions.HTTPError as e:
                        upgrade_guidance = {}
                    risk_lic, risk_sec, risk_ver, risk_act, risk_op = build_risk(component)

                    # if we don't have any vulnerability, print only the component
                    if vuln_count == 0:
                        csv_row = build_csv_row(repository=project['name'],
                                                component=component['componentName'],
                                                timestamp=scan_date,
                                                dep_type=dep_type_normalised,
                                                version=component['componentVersionName'],
                                                license_risk=risk_lic,
                                                security_risk=risk_sec,
                                                version_risk=risk_ver,
                                                activity_risk=risk_act,
                                                operational_risk=risk_op,
                                                vulnerability_id='',
                                                description='',
                                                url='',
                                                solution=build_solution(upgrade_guidance))
                        csv_writer.writerow(csv_row)
                    # if we have at least one vulnerability print each one on different row
                    for vulnid, description, url in zip(build_vulnerability(vuln),
                                                        build_vulnerability_description(vuln),
                                                        build_vulnerability_url(vuln)):
                        csv_row = build_csv_row(repository=project['name'],
                                                component=component['componentName'],
                                                timestamp=scan_date,
                                                dep_type=dep_type_normalised,
                                                version=component['componentVersionName'],
                                                license_risk=risk_lic,
                                                security_risk=risk_sec,
                                                version_risk=risk_ver,
                                                activity_risk=risk_act,
                                                operational_risk=risk_op,
                                                vulnerability_id=vulnid,
                                                description=description,
                                                url=url,
                                                solution=build_solution(upgrade_guidance))
                        csv_writer.writerow(csv_row)


if __name__ == '__main__':
    main()
