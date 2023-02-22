using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AspNetWebApiNew.Interfaces;
using AspNetWebApiNew.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace AspNetWebApiNew.Controllers
{
    //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/[controller]")]
    [ApiController]
    public class MyApiController : ControllerBase
    {
        private readonly IDataBookData dataBookData;
        public MyApiController(IDataBookData dBData)
        {
            dataBookData = dBData;
        }

        // GET api/MyApi
        [HttpGet]
        public IEnumerable<IDataBook> Get()
        {
            return dataBookData.GetAllDatabooks();
        }

        // GET api/MyApi/1
        [HttpGet("{id}")]
        [Authorize]
        public IDataBook GetDataBookById(int id)
        {
            return dataBookData.ReadDataBook(id);
        }

        // POST api/MyApi
        [HttpPost]
        [Authorize]
        //[Authorize(Roles = "Admin")]
        public void Post([FromBody] DataBook dataBook)
        {
            dataBookData.CreateDataBook(dataBook);
        }

        // PUT api/MyApi/3
        [HttpPut("{id}")]
        [Authorize(Roles = "Admin")]
        public void Put(int id, [FromBody] DataBook dataBook)
        {
            dataBookData.UpdateDataBookById(id, dataBook);
        }

        // DELETE api/MyApi/5
        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]
        public void Delete(int id)
        {
            dataBookData.DeleteDataBookById(id);
        }

    }
}
