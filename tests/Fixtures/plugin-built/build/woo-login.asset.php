<?php

// Stands in for the rolldown-generated manifest so the PHP suite can assert how enqueueAssets()
// consumes it without depending on `npm run build` having run. The real one is emitted by
// rolldown.config.ts; only the shape matters here.

return ['dependencies' => [], 'version' => 'testfixture000000000'];
