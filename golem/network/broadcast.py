import logging
import typing

from golem import model
from golem.core import variables
from golem.core.databuffer import DataBuffer


logger = logging.getLogger(__name__)


class BroadcastError(Exception):
    pass


class BroadcastList(list):
    @classmethod
    def from_bytes(cls, b: bytes) -> typing.List[model.Broadcast]:
        db = DataBuffer()
        db.append_bytes(b)
        result = []
        for cnt, broadcast_binary in enumerate(db.get_len_prefixed_bytes()):
            if cnt >= 10:
                break
            try:
                b = model.Broadcast.from_bytes(broadcast_binary)
                b.verify_signature(public_key=variables.BROADCAST_PUBKEY)
                result.append(b)
            except BroadcastError as e:
                logger.debug(
                    'Invalid broadcast received: %s. b=%r',
                    e,
                    broadcast_binary,
                )
            except Exception:
                logger.debug(
                    'Invalid broadcast received: %r',
                    broadcast_binary,
                    exc_info=True,
                )
        return result

    def to_bytes(self) -> bytes:
        db = DataBuffer()
        for broadcast in self:
            assert isinstance(broadcast, model.Broadcast)
            db.append_len_prefixed_bytes(broadcast.to_bytes())
        return db.read_all()


def prepare_handshake() -> BroadcastList:
    # XXX FIXME TODO remove my_private_key
    query = model.Broadcast.select().where(
        model.Broadcast.broadcast_type == model.Broadcast.TYPE.Version,
    )
    bl = BroadcastList()
    if query.exists():
        bl.append(query.order_by('-timestamp')[0])

    if not bl:  # XXX XXX
        import golem
        private_key = b"\x91M7\x06\x85\xd1\x15\xc7\x14\t\xe9\xca+\xef\xce\x15\xdf\xc5\xb6\x93]\xdc\xd0p\x0f\x18'\x92=3\n/"
        bl.append(model.Broadcast.create_and_sign(
            private_key=private_key,
            broadcast_type=model.Broadcast.TYPE.Version,
            data=golem.__version__.encode('ascii'),
        ))
    logger.error('Prepared handshake: %s', bl)
    return bl
