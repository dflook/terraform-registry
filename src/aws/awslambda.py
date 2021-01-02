class LambdaContext:
    function_name: str
    function_version: int
    invoked_function_arn: str
    memory_limit_in_mb: int
    aws_reqeuest_id: str
    log_group_name: str
    log_stream_name: str

    @staticmethod
    def get_remaining_time_in_millis() -> int:
        return 60 * 15 * 1000
