using System.ComponentModel.DataAnnotations;

namespace CrudApp.Models
{
    public class Note
    {
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public string? Title { get; set; }

        [Required]
        public string? Content { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.Now;
    }
}
