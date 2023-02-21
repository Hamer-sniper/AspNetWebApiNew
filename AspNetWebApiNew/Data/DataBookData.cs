using Microsoft.EntityFrameworkCore;
using AspNetWebApiNew.Models;
using AspNetWebApiNew.DataContext;
using AspNetWebApiNew.Interfaces;

namespace AspNetWebApiNew.Controllers
{
    public class DataBookData : IDataBookData
    {
        private readonly DataBookContext dBContext;

        public DataBookData(DataBookContext dB)
        {
            dBContext = dB;
        }

        /// <summary>
        /// Получить все записи из БД.
        /// </summary>
        /// <returns></returns>
        public List<DataBook> GetAllDatabooks()
        {
            return dBContext.DataBook.ToList();
        }

        /// <summary>
        /// Добавить запись в БД.
        /// </summary>
        /// <param name="dataBook">Запись</param>
        public void CreateDataBook(DataBook dataBook)
        {
            dBContext.DataBook.Add(dataBook);
            dBContext.SaveChanges();
        }

        /// <summary>
        /// Получить запись из БД.
        /// </summary>
        /// <param name="dataBookId">Id записи</param>
        /// <returns>Запись</returns>
        public DataBook ReadDataBook(int dataBookId)
        {
            return dBContext.DataBook.FirstOrDefault(d => d.Id == dataBookId);
        }

        /// <summary>
        /// Изменить запсиь в БД.
        /// </summary>
        /// <param name="dataBook">Запись</param>
        public void UpdateDataBook(DataBook dataBook)
        {
            dBContext.Entry(dataBook).State = EntityState.Modified;
            dBContext.SaveChanges();
        }

        /// <summary>
        /// Изменить запсиь в БД по Id.
        /// </summary>
        /// <param name="dataBookId">Id записи</param>
        /// <param name="dataBook">Запись</param>
        public void UpdateDataBookById(int dataBookId, DataBook dataBook)
        {
            var dataBookToModify = ReadDataBook(dataBookId);

            if (dataBookToModify != null)
            {
                dataBookToModify.Surname = dataBook.Surname;                
                dataBookToModify.Name = dataBook.Name;
                dataBookToModify.MiddleName = dataBook.MiddleName;
                dataBookToModify.TelephoneNumber = dataBook.TelephoneNumber;
                dataBookToModify.Adress = dataBook.Adress;
                dataBookToModify.Note = dataBook.Note;
                dBContext.SaveChanges();
            }
        }

        /// <summary>
        /// Удалить запись из БД.
        /// </summary>
        /// <param name="dataBook">Запись</param>
        public void DeleteDataBook(DataBook dataBook)
        {
            dBContext.DataBook.Remove(dataBook);
            dBContext.SaveChanges();
        }

        /// <summary>
        /// Удалить запись из БД по Id.
        /// </summary>
        /// <param name="dataBookId">Id записи</param>
        public void DeleteDataBookById(int dataBookId)
        {
            var dataBookToDelete = ReadDataBook(dataBookId);

            if (dataBookToDelete != null)
            {
                dBContext.DataBook.Remove(dataBookToDelete);
                dBContext.SaveChanges();
            }
        }
    }
}