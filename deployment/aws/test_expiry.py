import unittest
from unittest.mock import Mock

from botocore.exceptions import ClientError
from expiry import expire
from template import template

NAME = 'openid-aws-check-012345abcdef'
CONFIG = {'STACK': NAME, 'CREATED': '1000', 'EXPIRES': '15400'}
TAGS = [{'Key': 'OpenIDTest', 'Value': NAME}, {'Key': 'Environment', 'Value': 'disposable-test'}]


class ExpiryTests(unittest.TestCase):
    def setUp(self):
        self.rds, self.ec2 = Mock(), Mock()
        self.rds.describe_db_instances.return_value = {'DBInstances': [{'DBInstanceArn': 'test-arn', 'DBInstanceStatus': 'available'}]}
        self.rds.list_tags_for_resource.return_value = {'TagList': TAGS}
        self.ec2.get_paginator.return_value.paginate.return_value = [
            {'Reservations': [{'Instances': [{'InstanceId': 'i-test', 'Tags': TAGS}]}]}]

    def test_waits_without_resource_calls(self):
        self.assertEqual('WAITING', expire(CONFIG, 15399, self.rds, self.ec2)['state'])
        self.assertEqual([], self.rds.mock_calls)
        self.assertEqual([], self.ec2.mock_calls)

    def test_deletes_only_tagged_resources_after_deadline(self):
        result = expire(CONFIG, 15400, self.rds, self.ec2)
        self.assertEqual('deleting', result['database'])
        self.rds.delete_db_instance.assert_called_once_with(DBInstanceIdentifier=NAME, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
        self.ec2.terminate_instances.assert_called_once_with(InstanceIds=['i-test'])

    def test_no_deletion_for_invalid_name_or_lifetime(self):
        for change in ({'STACK': 'production'}, {'EXPIRES': '1000'}, {'EXPIRES': '15401'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                expire(CONFIG | change, 99999, self.rds, self.ec2)
        self.rds.delete_db_instance.assert_not_called()
        self.ec2.terminate_instances.assert_not_called()

    def test_wrong_database_tags_prevent_deletion(self):
        for tags in ([], TAGS[:1], [{'Key': 'OpenIDTest', 'Value': 'another-stack'}]):
            self.rds.list_tags_for_resource.return_value = {'TagList': tags}
            with self.assertRaises(ValueError):
                expire(CONFIG, 15400, self.rds, self.ec2)
        self.rds.delete_db_instance.assert_not_called()

    def test_wrong_instance_tags_prevent_termination(self):
        self.ec2.get_paginator.return_value.paginate.return_value = [
            {'Reservations': [{'Instances': [{'InstanceId': 'i-other', 'Tags': []}]}]}]
        with self.assertRaises(ValueError):
            expire(CONFIG, 15400, self.rds, self.ec2)
        self.ec2.terminate_instances.assert_not_called()

    def test_deleted_database_does_not_prevent_runner_cleanup(self):
        self.rds.describe_db_instances.side_effect = ClientError({'Error': {'Code': 'DBInstanceNotFound'}}, 'DescribeDBInstances')
        self.assertEqual('absent', expire(CONFIG, 15400, self.rds, self.ec2)['database'])
        self.ec2.terminate_instances.assert_called_once()

    def test_creating_database_is_retried_and_runner_removed(self):
        self.rds.delete_db_instance.side_effect = ClientError({'Error': {'Code': 'InvalidDBInstanceState'}}, 'DeleteDBInstance')
        self.assertEqual('retry', expire(CONFIG, 15400, self.rds, self.ec2)['database'])
        self.ec2.terminate_instances.assert_called_once()

    def test_unknown_aws_error_is_not_reported_as_success(self):
        self.rds.describe_db_instances.side_effect = ClientError({'Error': {'Code': 'AccessDenied'}}, 'DescribeDBInstances')
        with self.assertRaises(ClientError):
            expire(CONFIG, 15400, self.rds, self.ec2)

    def test_already_deleting_database_is_idempotent(self):
        self.rds.describe_db_instances.return_value['DBInstances'][0]['DBInstanceStatus'] = 'deleting'
        self.assertEqual('deleting', expire(CONFIG, 15400, self.rds, self.ec2)['database'])
        self.rds.delete_db_instance.assert_not_called()

    def test_all_instance_pages_are_processed(self):
        self.ec2.get_paginator.return_value.paginate.return_value = [
            {'Reservations': [{'Instances': [{'InstanceId': i, 'Tags': TAGS}]}]} for i in ('i-one', 'i-two')]
        self.assertEqual(['i-one', 'i-two'], expire(CONFIG, 15400, self.rds, self.ec2)['instances'])

    def test_template_contains_expiry_before_billable_resources(self):
        resources = template('ami-0123456789abcdef0', 1000)['Resources']
        self.assertIn('ExpiryPermission', resources['Database']['DependsOn'])
        self.assertIn('ExpiryPermission', resources['Runner']['DependsOn'])
        self.assertEqual('15400', resources['Expiry']['Properties']['Environment']['Variables']['EXPIRES'])
        self.assertEqual('Delete', resources['Database']['DeletionPolicy'])
        self.assertEqual('standard', resources['Runner']['Properties']['CreditSpecification']['CPUCredits'])


if __name__ == '__main__':
    unittest.main()
