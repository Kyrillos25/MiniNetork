using DataAccessLayer.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RepositoryLayer.Repositories.Interface
{
    public interface IRepository<T> where T : BaseEntity
    {
        T Get(int id);
        IQueryable<T> GetAll();
        void Add(T entity);

    }
}
