"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError, Connector
from .operations import operations, _check_health

logger = get_logger('mandiant-threat-intel')


class MandiantThreatIntel(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            # todo let call connector take it from _info
            connector_info = {"connector_name": self._info_json.get('name'),
                              "connector_version": self._info_json.get('version')}
            operation = operations.get(operation)
            # now was ingesting it from integration separately
            # changes for fcp/tip specific so it dsnt break on fsr
            if 'connector_name' in kwargs:
                kwargs.pop('connector_name')
            return operation(config, params, connector_info, **kwargs)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    def check_health(self, config):
        logger.info('starting health check')
        connector_info = {"connector_name": self._info_json.get('name'),
                          "connector_version": self._info_json.get('version')}
        _check_health(config, connector_info)
        logger.info('completed health check no errors')
