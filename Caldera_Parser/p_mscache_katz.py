import re
from app.utility.base_parser import BaseParser, PARSER_SIGNALS_FAILURE
from app.objects.secondclass.c_fact import Fact
from app.objects.secondclass.c_relationship import Relationship


class Parser(BaseParser):

    def parse(self, blob):
        relationships = []
        cached_creds = re.findall(r"User *: (.*)\nMsCacheV2 *: (.*)", blob)
        if len(cached_creds) >= 1:
            for o in cached_creds:
                for mp in self.mappers:
                    relationships.append(
                        Relationship(source=Fact(mp.source, o[0]),
                                     edge=mp.edge,
                                     target=Fact(mp.target, o[1]))
                    )
            return relationships
        return [PARSER_SIGNALS_FAILURE]
