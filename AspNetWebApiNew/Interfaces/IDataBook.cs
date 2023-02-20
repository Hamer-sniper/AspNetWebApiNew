namespace AspNetWebApiNew.Interfaces
{
    public interface IDataBook
    {
        /// <summary>
        /// Количество записей.
        /// </summary>
        public static int Count { get; set; }

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
    }
}