(function () {
  'use strict';

  var connectlyOrigin = localStorage.getItem('hbw_connectly_origin_v1') || 'https://localhost:3000';

  window.HBW_CONFIG = {
    connectlyOrigin: connectlyOrigin,
    connectlyRegisterUrl: connectlyOrigin + '/api/register-honeybound-account'
  };
})();
