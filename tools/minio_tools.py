from functools import wraps
from pylon.core.tools import log


def space_monitor(f):
    '''Decorator to calculate delta when a file is uploaded or removed from a bucket.
       Usage plugin uses it to check max storage space.
    '''
    @wraps(f)
    def wrapper(*args, **kwargs):
        client = args[0]
        bucket = kwargs.get('bucket') or args[1]
        filename = kwargs.get('filename') or args[-1]
        size_before = client.get_file_size(bucket, filename)
        result = f(*args, **kwargs)
        size_after = client.get_file_size(bucket, filename)
        payload = {
            'project_id': client.project['id'] if client.project else None,
            'current_delta': size_after - size_before, 
            'integration_id': client.integration_id,
            'is_local': client.is_local
        }
        client.event_manager.fire_event('usage_space_monitor', payload)
        return result
    return wrapper


def throughput_monitor(client, file_size: int, project_id: int = None):
    '''Function to calculate throughput when a file is read, uploaded or downloaded 
       from a bucket. Usage plugin uses it to check platform and project throughput.
    '''
    if client.integration_id:
        payload = {
            'project_id': client.project['id'] if client.project else project_id,
            'file_size': file_size, 
            'integration_id': client.integration_id,
            'is_local': client.is_local
        }
        client.event_manager.fire_event('usage_throughput_monitor', payload)
