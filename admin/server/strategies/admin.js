'use strict';

const { getService } = require('../utils');

/** @type {import('.').AuthenticateFunction} */
const authenticate = async ctx => {
  console.log('src/admin/server/strategies/admin.js......authenticate')
  const { authorization } = ctx.request.header;

  if (!authorization) {
    return { authenticated: false };
  }

  const parts = authorization.split(/\s+/);
  
    // PBCS-16 ----------
    if (parts[0].toLowerCase() !== 'bearer' && parts[0].toLowerCase() !== 'entkctoken' || parts.length !== 2) {
      return { authenticated: false };
    }
    const token = parts[1];
    let payload = {};
    let queryObj = {};
    if (parts && parts[0] && parts[0].toLowerCase() === 'bearer') {
      payload = getService('token').decodeJwtToken(token);
      queryObj = { id: payload.payload.id };
    } else {
      await getService('token').decodeJwtKCToken(token).then((res) => {
        console.log('response: ', res);
        payload = { id: res.id, userName: res.userName, isValid: true };
        queryObj = { username: payload.userName };
        console.log('Verified kc token obj: ', payload);
      }).catch((err) => {
        console.log('Error in decode kc token(Admin request) : ', err);
        payload = { id: null, username: null, isValid: false };
      });
    }
  // ----------
  
    if (!payload.isValid) {
      return { authenticated: false };
    }
  
    // Existing code
    // const user = await strapi
    //   .query('admin::user')
    //   .findOne({ where: { id: payload.id }, populate: ['roles'] });
  
    const user = await strapi
      .query('admin::user')
      .findOne({ where: queryObj, populate: ['roles'] });
  
      console.log('strapi db user: ', user);

  if (!user || !(user.isActive === true)) {
    return { authenticated: false };
  }

  const userAbility = await getService('permission').engine.generateUserAbility(user);

  ctx.state.userAbility = userAbility;
  ctx.state.user = user;

  return { authenticated: true, credentials: user };
};

/** @type {import('.').AuthStrategy} */
module.exports = {
  name: 'admin',
  authenticate,
};
