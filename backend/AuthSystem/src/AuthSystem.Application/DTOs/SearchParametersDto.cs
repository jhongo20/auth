namespace AuthSystem.Application.DTOs
{
    public class SearchParametersDto
    {
        private int _pageSize = 10;
        private int _pageNumber = 1;

        public string SearchTerm { get; set; }
        public string SortBy { get; set; }
        public bool SortDescending { get; set; }

        public int PageNumber
        {
            get => _pageNumber;
            set => _pageNumber = value < 1 ? 1 : value;
        }

        public int PageSize
        {
            get => _pageSize;
            set => _pageSize = value > 50 ? 50 : (value < 1 ? 10 : value);
        }

        public string FilterField { get; set; }
        public string FilterValue { get; set; }
    }
}