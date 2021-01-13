package web.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import web.model.Role;
import web.model.User;
import web.service.UserService;

import java.util.List;

@Controller
@RequestMapping("/")
public class LoginController {

    private final UserService userService;

    @Autowired
    public LoginController(UserService userService) {
        this.userService = userService;
    }


    @GetMapping("/admin")
    public String index1(Model model) {
        model.addAttribute("users", userService.getAllUsers());
        return "admin";
    }


    @PostMapping(value = "admin/user/new")
    public String create(@ModelAttribute("user") User user) {
        userService.save(user);
        return "redirect:/admin";
    }


    @GetMapping("/user/{id}")
    public String show(Model model, @PathVariable("id") long id) {
        User currentuser = (User) SecurityContextHolder.getContext()
                .getAuthentication()
                .getPrincipal();
        if(currentuser.getId()!=id&&currentuser.getRoles().stream().noneMatch((x->x.getName().contains("ROLE_ADMIN")))){
            return "redirect:/user/" + currentuser.getId();
        }
        model.addAttribute("user", userService.show(id));
        return "user";
    }


    @GetMapping("admin/user/new")
    public String newUser(@ModelAttribute("user") User user, Model model) {
        List<Role> allRoles = userService.getRoles();
        model.addAttribute("allRoles", allRoles);
        return "new";
    }


    @RequestMapping(value = "/admin/edit/{id}", method = {RequestMethod.POST, RequestMethod.GET})
    public String edit(@PathVariable("id") Long id, @ModelAttribute("user") User user) {
        userService.update(id, user);
        return "redirect:/admin";
    }

    @GetMapping("/admin/user/edit/{id}")
    public String editforadmin(Model model, @PathVariable("id") long id) {
        model.addAttribute("user", userService.show(id));
        List<Role> allRoles = userService.getRoles();
        model.addAttribute("allRoles", allRoles);
        return "edit";
    }


    @DeleteMapping("admin/{id}")
    public String delete(@PathVariable("id") long id) {
        userService.delete(id);
        return "redirect:/admin";
    }
}
