import re
from app.utility.base_parser import BaseParser, PARSER_SIGNALS_FAILURE

class Parser(BaseParser):

    def parse(self, blob):
        match = re.search(r"ReturnValue = (\d);", blob)
        return self._is_valid_return(match)

    @staticmethod
    def _is_valid_return(match):
        if match:
            return_code = int(match.group(1))
            if return_code == 0:
                return []
        return [PARSER_SIGNALS_FAILURE]
