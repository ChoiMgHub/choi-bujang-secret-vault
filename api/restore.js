import config from '../aleph.config.json' with { type: 'json' };
import { createRestoreHandler } from '../src/restore-api.mjs';

export default createRestoreHandler({ config });
