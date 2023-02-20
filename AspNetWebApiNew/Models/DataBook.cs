using AspNetWebApiNew.Interfaces;

namespace AspNetWebApiNew.Models
{
    public class DataBook : IDataBook
    {
        #region Свойства 
        /// <summary>
        /// Количество записей.
        /// </summary>
        public static int Count { get; set; } = 0;

        /// <summary>
        /// ID.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Фамилия.
        /// </summary>
        public string Surname { get; set; }

        /// <summary>
        /// Имя.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Отчество.
        /// </summary>
        public string MiddleName { get; set; }

        /// <summary>
        /// Номер телефона.
        /// </summary>
        public string TelephoneNumber { get; set; }

        /// <summary>
        /// Адрес.
        /// </summary>
        public string Adress { get; set; }

        /// <summary>
        /// Описание.
        /// </summary>
        public string Note { get; set; }
        #endregion

        #region Конструкторы
        /// <summary>
        /// Конструктор со всеми параметрами.
        /// </summary>
        /// <param name="surname"></param>
        /// <param name="name"></param>
        /// <param name="middleName"></param>
        /// <param name="telephoneNumber"></param>
        /// <param name="adress"></param>
        public DataBook(string surname, string name, string middleName, string telephoneNumber, string adress, string note)
        {
            Count++;
            //Id = Count;
            Surname = surname;
            Name = name;
            MiddleName = middleName;
            TelephoneNumber = telephoneNumber;
            Adress = adress;
            Note = note;
        }

        /// <summary>
        /// Конструктор с автозаполнением.
        /// </summary>
        public DataBook()
        {         
            Count++;
            //Id = Count;
            Surname = $"Тестовая фамилия {Count}";
            Name = $"Тестовое имя {Count}";
            MiddleName = $"Тестовое отчество {Count}";
            TelephoneNumber = $"{Count}{Count}{Count}{Count}{Count}{Count}{Count}{Count}{Count}{Count}{Count}{Count}".Remove(10);
            Adress = $"Страна {Count}, город {Count}, улица {Count}, дом {Count}";
            Note = $"Описание для соответсвующего контакта {Count}";
        }
        #endregion
    }
}
