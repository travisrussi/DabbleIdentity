using System;
using System.ComponentModel.Composition;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Authorization.Mvc;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels;
using NLog;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.Controllers
{
    [ClaimsAuthorize(Constants.Actions.Administration, Constants.Resources.Configuration)]
    public class UserController : Controller
    {
        static Logger logger = LogManager.GetCurrentClassLogger();

        [Import]
        public IUserManagementRepository UserManagementRepository { get; set; }

        public UserController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public UserController(IUserManagementRepository userManagementRepository)
        {
            UserManagementRepository = userManagementRepository;
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Filter(string filter)
        {
            return RedirectToAction("Index", new { filter = filter });
        }

        public ActionResult Index(int page = 1, string filter = null)
        {
            var vm = new UsersViewModel(UserManagementRepository, page, filter);
            return View("Index", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(int page, string filter, string action, UserDeleteModel[] list)
        {
            if (action == "new") return Create();
            if (action == "delete") return Delete(page, filter, list);

            ModelState.AddModelError("", Resources.UserController.InvalidAction);
            var vm = new UsersViewModel(UserManagementRepository, page, filter);
            return View("Index", vm);
        }

        public ActionResult Create()
        {
            var rolesvm = new UserRolesViewModel(UserManagementRepository, String.Empty);
            var vm = new UserInputModel();
            vm.Roles = rolesvm.RoleAssignments;
            return View("Create", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(UserInputModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    this.UserManagementRepository.CreateUser(model.Username, model.Password);
                    if (model.Roles != null)
                    {
                        var roles = model.Roles.Where(x => x.InRole).Select(x => x.Role);
                        if (roles.Any())
                        {
                            this.UserManagementRepository.SetRolesForUser(model.Username, roles);
                        }
                    }
                    TempData["Message"] = Resources.UserController.UserCreated;
                    return RedirectToAction("Index", new { filter = model.Username });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception e)
                {
                    logger.LogException(LogLevel.Error, "Error while Creating User", e);
                    ModelState.AddModelError("", Resources.UserController.ErrorCreatingUser);
                }
            }

            return View("Create", model);
        }

        private ActionResult Delete(int page, string filter, UserDeleteModel[] list)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    foreach (var name in list.Where(x => x.Delete).Select(x => x.Username))
                    {
                        this.UserManagementRepository.DeleteUser(name);
                    }
                    TempData["Message"] = Resources.UserController.UsersDeleted;
                    return RedirectToAction("Index", new { page, filter });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch
                {
                    ModelState.AddModelError("", Resources.UserController.ErrorDeletingUser);
                }
            }
            return Index(page, filter);
        }

        public ActionResult Roles(string username)
        {
            var vm = new UserRolesViewModel(this.UserManagementRepository, username);
            return View("Roles", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Roles(string username, UserRoleAssignment[] roleAssignments)
        {
            var vm = new UserRolesViewModel(this.UserManagementRepository, username);
            if (ModelState.IsValid)
            {
                try
                {
                    var currentRoles =
                        roleAssignments.Where(x => x.InRole).Select(x => x.Role);
                    this.UserManagementRepository.SetRolesForUser(username, currentRoles);
                    TempData["Message"] = Resources.UserController.RolesAssignedSuccessfully;
                    return RedirectToAction("Roles", new { username });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch
                {
                    ModelState.AddModelError("", Resources.UserController.ErrorAssigningRoles);
                }
            }

            return View("Roles", vm);
        }

        [Authorize]
        public ActionResult Profile(string id)
        {
            try
            {
                //not needed authorize 
                if (HttpContext.User.Identity.IsAuthenticated)
                {
                    var profile = UserManagementRepository.GetByUsername(id);
                    return View(profile);
                }
            }
            catch (Exception ex)
            {
                //todo: logging.
                logger.LogException(LogLevel.Error, "An error occured during opening the myprofile page: ", ex);
                System.Diagnostics.Debug.WriteLine("An error occured during opening the myprofile page : {0}", ex.Message);
            }

            return new HttpStatusCodeResult(System.Net.HttpStatusCode.Unauthorized);
        }

    }
}