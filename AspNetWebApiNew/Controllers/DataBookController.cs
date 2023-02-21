using Microsoft.AspNetCore.Mvc;
using AspNetWebApiNew.Models;
using AspNetWebApiNew.Interfaces;
using Microsoft.AspNetCore.Authorization;

namespace AspNetWebApiNew.Controllers
{
    public class DataBookController : Controller
    {
        private readonly IDataBookData dataBookData;
        public DataBookController(IDataBookData dBData)
        {
            dataBookData = dBData;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Index()
        {
            ViewBag.DataBook = dataBookData.GetAllDatabooks();
            return View();
        }

        [HttpGet]
        [Authorize]
        public IActionResult GetDataBook(int dataBookId)
        {
            return View(dataBookData.ReadDataBook(dataBookId));
        }

        [HttpGet]
        [Authorize]
        public IActionResult AddDataBook()
        {
            return View();
        }

        [HttpPost]
        [Authorize]
        public IActionResult AddDataFromField(DataBook dataBook)
        {
            dataBookData.CreateDataBook(dataBook);
            return Redirect("~/");
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult EditDataBook(int dataBookId)
        {
            return View(dataBookData.ReadDataBook(dataBookId));
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult EditDataFromField(DataBook dataBook)
        {
            dataBookData.UpdateDataBook(dataBook);
            return Redirect("~/");
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult DeleteDataBook(int dataBookId)
        {
            return View(dataBookData.ReadDataBook(dataBookId));
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult DeleteDataFromField(DataBook dataBook)
        {
            dataBookData.DeleteDataBook(dataBook);
            return Redirect("~/");
        }
    }
}