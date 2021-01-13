package web.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import web.dao.UserDao;

@Service
class UserDetailsServiceImpl implements UserDetailsService {
    private final UserDao userDao;

    @Autowired
    public UserDetailsServiceImpl(UserDao userDao) {
        this.userDao = userDao;
    }


    //    @Override
//    @Transactional
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        UserDetails loadedUser;
//
//        try {
//            User client = userDao.findByUsername(username);
//            loadedUser = new org.springframework.security.core.userdetails.User(
//                    client.getUsername(), client.getAge(), client.getPassword(),
//                    client.getRoles());
//        } catch (Exception repositoryProblem) {
//            throw new InternalAuthenticationServiceException(repositoryProblem.getMessage(), repositoryProblem);
//        }
//        return loadedUser;
//    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userDao.findByUsername(username);
    }

}